"""协调认证、批次、测试和放行门禁的应用服务。"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from .analytics import confidence_interval, summarize_spectrum, yield_rate
from .auth import Auth
from .storage import certificate_event, connect, event, transaction, utcnow


def _parse_utc(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class PhotonService:
    def __init__(self, database: str = ":memory:"):
        self.db = connect(database)
        self.auth = Auth(self.db)

    def bootstrap_admin(self, user_id: str = "admin", password: str = "photon-admin") -> None:
        try:
            self.auth.create_user(user_id, password, "admin")
        except Exception:
            pass

    def register_certificate(self, token: str, certificate_id: str, instrument: str, valid_from: str, valid_until: str, issued_at: str | None = None) -> dict:
        """登记校准证书新版本；历史版本保留，仅最新版本参与测量校验。"""
        actor = self.auth.require(token, "cert_register")
        if not certificate_id.strip() or not instrument.strip():
            raise ValueError("certificate_id and instrument are required")
        start = _parse_utc(valid_from, "valid_from")
        end = _parse_utc(valid_until, "valid_until")
        if end <= start:
            raise ValueError("valid_until must be after valid_from")
        issued = utcnow() if issued_at is None else _parse_utc(issued_at, "issued_at").isoformat()
        with transaction(self.db):
            row = self.db.execute("SELECT MAX(version) FROM calibration_certificates WHERE certificate_id=?", (certificate_id,)).fetchone()
            version = (row[0] or 0) + 1
            self.db.execute(
                "INSERT INTO calibration_certificates VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (certificate_id, version, instrument, issued, start.isoformat(), end.isoformat(), "active", actor.user_id, None, None, None),
            )
            certificate_event(self.db, certificate_id, "certificate.registered", actor.user_id, {"version": version, "instrument": instrument, "valid_from": start.isoformat(), "valid_until": end.isoformat()})
        return self.get_certificate(token, certificate_id)

    def get_certificate(self, token: str, certificate_id: str) -> dict:
        self.auth.require(token, "read")
        row = self.db.execute(
            "SELECT * FROM calibration_certificates WHERE certificate_id=? ORDER BY version DESC LIMIT 1", (certificate_id,)
        ).fetchone()
        if not row:
            raise KeyError(certificate_id)
        return dict(row)

    def list_certificates(self, token: str, instrument: str | None = None) -> list[dict]:
        self.auth.require(token, "read")
        if instrument is None:
            rows = self.db.execute("SELECT * FROM calibration_certificates ORDER BY certificate_id, version").fetchall()
        else:
            rows = self.db.execute("SELECT * FROM calibration_certificates WHERE instrument=? ORDER BY certificate_id, version", (instrument,)).fetchall()
        return [dict(r) for r in rows]

    def _active_certificate(self, instrument: str, moment: datetime) -> dict | None:
        row = self.db.execute(
            """SELECT * FROM calibration_certificates
               WHERE instrument=? AND status='active' AND valid_from<=? AND valid_until>=?
               ORDER BY version DESC LIMIT 1""",
            (instrument, moment.isoformat(), moment.isoformat()),
        ).fetchone()
        return dict(row) if row else None

    def verify_certificate(self, token: str, instrument: str, at: str | None = None) -> dict:
        """测量前校验：仪器在指定时刻必须持有有效且未撤销的校准证书。"""
        self.auth.require(token, "measure")
        moment = _parse_utc(at, "at") if at is not None else _parse_utc(utcnow(), "at")
        certificate = self._active_certificate(instrument, moment)
        if certificate is None:
            raise PermissionError(f"instrument {instrument} has no valid calibration certificate")
        return {"instrument": instrument, "certificate_id": certificate["certificate_id"], "certificate_version": certificate["version"], "valid_until": certificate["valid_until"]}

    def revoke_certificate(self, token: str, certificate_id: str, reason: str) -> dict:
        """撤销证书最新版本；已写入的测量记录保持不变。"""
        actor = self.auth.require(token, "cert_revoke")
        if not reason.strip():
            raise ValueError("revoke reason is required")
        with transaction(self.db):
            row = self.db.execute(
                "SELECT * FROM calibration_certificates WHERE certificate_id=? ORDER BY version DESC LIMIT 1", (certificate_id,)
            ).fetchone()
            if not row:
                raise KeyError(certificate_id)
            if row["status"] == "revoked":
                raise ValueError("certificate already revoked")
            now = utcnow()
            self.db.execute(
                "UPDATE calibration_certificates SET status='revoked',revoked_at=?,revoked_by=?,revoke_reason=? WHERE certificate_id=? AND version=?",
                (now, actor.user_id, reason, certificate_id, row["version"]),
            )
            certificate_event(self.db, certificate_id, "certificate.revoked", actor.user_id, {"version": row["version"], "reason": reason})
        return self.get_certificate(token, certificate_id)

    def certificate_audit(self, token: str, certificate_id: str) -> list[dict]:
        """证书生命周期审计，仅质量人员和管理员可见。"""
        self.auth.require(token, "audit")
        return [dict(r) for r in self.db.execute("SELECT * FROM certificate_events WHERE certificate_id=? ORDER BY event_id", (certificate_id,)).fetchall()]

    def create_lot(self, token: str, lot_id: str, product: str, process_rev: str, wafer_count: int) -> dict:
        actor = self.auth.require(token, "submit")
        if wafer_count <= 0 or not lot_id.strip() or not process_rev.strip():
            raise ValueError("lot fields are invalid")
        now = utcnow()
        with transaction(self.db):
            self.db.execute("INSERT INTO chip_lots VALUES(?,?,?,?,?,?,?,?)", (lot_id, product, process_rev, wafer_count, "engineering", actor.user_id, now, now))
            event(self.db, lot_id, "created", actor.user_id, {"product": product, "process_rev": process_rev})
        return self.get_lot(token, lot_id)

    def get_lot(self, token: str, lot_id: str) -> dict:
        self.auth.require(token, "read")
        row = self.db.execute("SELECT * FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone()
        if not row:
            raise KeyError(lot_id)
        return dict(row)

    def add_measurement(self, token: str, lot_id: str, wavelength_nm: float, response: float, noise: float, instrument: str) -> dict:
        actor = self.auth.require(token, "measure")
        measurement_id = uuid.uuid4().hex
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                raise KeyError(lot_id)
            # 测量前校验：仪器必须持有当前有效且未撤销的校准证书，
            # 证书编号与版本随测量记录固化，证书后续变更不改写历史。
            certificate = self._active_certificate(instrument, _parse_utc(utcnow(), "measured_at"))
            if certificate is None:
                raise PermissionError(f"instrument {instrument} has no valid calibration certificate")
            self.db.execute(
                "INSERT INTO measurements VALUES(?,?,?,?,?,?,?,?,?,?)",
                (measurement_id, lot_id, float(wavelength_nm), float(response), float(noise), instrument, actor.user_id, utcnow(), certificate["certificate_id"], certificate["version"]),
            )
            event(self.db, lot_id, "measurement", actor.user_id, {"measurement_id": measurement_id, "wavelength_nm": wavelength_nm, "certificate_id": certificate["certificate_id"], "certificate_version": certificate["version"]})
        return {"measurement_id": measurement_id, "lot_id": lot_id, "certificate_id": certificate["certificate_id"], "certificate_version": certificate["version"]}

    def analyze(self, token: str, lot_id: str) -> dict:
        self.auth.require(token, "analyze")
        rows = self.db.execute("SELECT wavelength_nm,response FROM measurements WHERE lot_id=? ORDER BY wavelength_nm", (lot_id,)).fetchall()
        if len(rows) < 3:
            raise ValueError("three measurements are required")
        summary = summarize_spectrum([r[0] for r in rows], [r[1] for r in rows])
        rates = yield_rate(self.get_lot(token, lot_id)["wafer_count"], sum(1 for r in rows if r[1] >= 0.8), 0)
        ci = confidence_interval([r[1] for r in rows])
        return {"lot_id": lot_id, "spectrum": summary.__dict__, "yield": rates, "response_ci": ci}

    def approve(self, token: str, lot_id: str, decision: str, reason: str) -> dict:
        actor = self.auth.require(token, "approve")
        if decision not in {"release", "hold", "reject"} or not reason.strip():
            raise ValueError("decision and reason are required")
        with transaction(self.db):
            self.db.execute("INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?)", (lot_id, actor.user_id, decision, reason, utcnow()))
            status = {"release": "released", "hold": "hold", "reject": "rejected"}[decision]
            self.db.execute("UPDATE chip_lots SET status=?,updated_at=? WHERE lot_id=?", (status, utcnow(), lot_id))
            event(self.db, lot_id, "approval", actor.user_id, {"decision": decision, "reason": reason})
        return self.get_lot(token, lot_id)

    def audit(self, token: str, lot_id: str) -> list[dict]:
        self.auth.require(token, "read")
        return [dict(r) for r in self.db.execute("SELECT * FROM lot_events WHERE lot_id=? ORDER BY event_id", (lot_id,)).fetchall()]
