"""协调认证、批次、测试和放行门禁的应用服务。"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from .analytics import confidence_interval, summarize_spectrum, yield_rate
from .auth import Auth
from .storage import certificate_event, connect, event, transaction, utcnow


def _parse_time(value: str) -> str:
    """把 ISO 时间归一化为 UTC 文本，保证证书有效期可按字符串比较。"""
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"invalid timestamp: {value!r}") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


class PhotonService:
    def __init__(self, database: str = ":memory:"):
        self.db = connect(database)
        self.auth = Auth(self.db)

    def bootstrap_admin(self, user_id: str = "admin", password: str = "photon-admin") -> None:
        try:
            self.auth.create_user(user_id, password, "admin")
        except Exception:
            pass

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

    def register_certificate(self, token: str, cert_id: str, instrument: str, issuer: str, valid_from: str, valid_until: str) -> dict:
        actor = self.auth.require(token, "admin")
        cert_id, instrument, issuer = cert_id.strip(), instrument.strip(), issuer.strip()
        if not cert_id or not instrument or not issuer:
            raise ValueError("certificate fields are invalid")
        start, end = _parse_time(valid_from), _parse_time(valid_until)
        if start >= end:
            raise ValueError("valid_from must be before valid_until")
        with transaction(self.db):
            if self.db.execute("SELECT 1 FROM certificate_revocations WHERE cert_id=?", (cert_id,)).fetchone():
                raise ValueError("certificate was revoked; register a new certificate id")
            row = self.db.execute("SELECT MAX(version) FROM calibration_certificates WHERE cert_id=?", (cert_id,)).fetchone()
            version = (row[0] or 0) + 1
            self.db.execute("INSERT INTO calibration_certificates VALUES(?,?,?,?,?,?,?,?)", (cert_id, version, instrument, issuer, start, end, actor.user_id, utcnow()))
            certificate_event(self.db, cert_id, "registered", actor.user_id, {"instrument": instrument, "version": version, "valid_from": start, "valid_until": end, "issuer": issuer})
        return self.get_certificate(token, cert_id)

    def get_certificate(self, token: str, cert_id: str) -> dict:
        self.auth.require(token, "read")
        rows = self.db.execute("SELECT * FROM calibration_certificates WHERE cert_id=? ORDER BY version", (cert_id,)).fetchall()
        if not rows:
            raise KeyError(cert_id)
        revocation = self.db.execute("SELECT * FROM certificate_revocations WHERE cert_id=?", (cert_id,)).fetchone()
        latest = rows[-1]
        return {
            "cert_id": cert_id, "instrument": latest["instrument"], "issuer": latest["issuer"],
            "version": latest["version"], "valid_from": latest["valid_from"], "valid_until": latest["valid_until"],
            "status": "revoked" if revocation else "active",
            "versions": [dict(r) for r in rows],
            "revocation": dict(revocation) if revocation else None,
        }

    def _calibration_status(self, instrument: str, moment: str) -> dict:
        rows = self.db.execute(
            "SELECT c.cert_id,c.version,c.valid_from,c.valid_until,"
            " EXISTS(SELECT 1 FROM certificate_revocations r WHERE r.cert_id=c.cert_id) AS revoked"
            " FROM calibration_certificates c WHERE c.instrument=?"
            " ORDER BY c.valid_from DESC,c.version DESC", (instrument,)).fetchall()
        covering = [r for r in rows if not r["revoked"] and r["valid_from"] <= moment <= r["valid_until"]]
        if covering:
            best = covering[0]
            return {"valid": True, "cert_id": best["cert_id"], "version": best["version"], "valid_from": best["valid_from"], "valid_until": best["valid_until"]}
        if not rows:
            reason = "no_certificate"
        elif all(r["revoked"] for r in rows) or any(r["revoked"] and r["valid_from"] <= moment <= r["valid_until"] for r in rows):
            reason = "revoked"
        elif all(r["valid_until"] < moment for r in rows if not r["revoked"]):
            reason = "expired"
        elif all(r["valid_from"] > moment for r in rows if not r["revoked"]):
            reason = "not_yet_valid"
        else:
            reason = "expired"
        return {"valid": False, "reason": reason}

    def certificate_validity(self, token: str, instrument: str, at: str | None = None) -> dict:
        self.auth.require(token, "read")
        moment = _parse_time(at) if at else utcnow()
        return {"instrument": instrument, "at": moment, **self._calibration_status(instrument, moment)}

    def revoke_certificate(self, token: str, cert_id: str, reason: str) -> dict:
        actor = self.auth.require(token, "admin")
        if not reason.strip():
            raise ValueError("revoke reason is required")
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM calibration_certificates WHERE cert_id=?", (cert_id,)).fetchone():
                raise KeyError(cert_id)
            if self.db.execute("SELECT 1 FROM certificate_revocations WHERE cert_id=?", (cert_id,)).fetchone():
                raise ValueError("certificate already revoked")
            self.db.execute("INSERT INTO certificate_revocations VALUES(?,?,?,?)", (cert_id, reason.strip(), actor.user_id, utcnow()))
            certificate_event(self.db, cert_id, "revoked", actor.user_id, {"reason": reason.strip()})
        return self.get_certificate(token, cert_id)

    def certificate_audit(self, token: str, cert_id: str) -> list[dict]:
        self.auth.require(token, "audit")
        return [dict(r) for r in self.db.execute("SELECT * FROM certificate_events WHERE cert_id=? ORDER BY event_id", (cert_id,)).fetchall()]

    def add_measurement(self, token: str, lot_id: str, wavelength_nm: float, response: float, noise: float, instrument: str) -> dict:
        actor = self.auth.require(token, "measure")
        measurement_id = uuid.uuid4().hex
        now = utcnow()
        with transaction(self.db):
            if not self.db.execute("SELECT 1 FROM chip_lots WHERE lot_id=?", (lot_id,)).fetchone():
                raise KeyError(lot_id)
            status = self._calibration_status(instrument, now)
            if not status["valid"]:
                raise ValueError(f"instrument {instrument!r} has no valid calibration certificate: {status['reason']}")
            self.db.execute(
                "INSERT INTO measurements(measurement_id,lot_id,wavelength_nm,response,noise,instrument,operator,measured_at,cert_id,cert_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (measurement_id, lot_id, float(wavelength_nm), float(response), float(noise), instrument, actor.user_id, now, status["cert_id"], status["version"]))
            event(self.db, lot_id, "measurement", actor.user_id, {"measurement_id": measurement_id, "wavelength_nm": wavelength_nm, "cert_id": status["cert_id"], "cert_version": status["version"]})
        return {"measurement_id": measurement_id, "lot_id": lot_id, "cert_id": status["cert_id"], "cert_version": status["version"]}

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
