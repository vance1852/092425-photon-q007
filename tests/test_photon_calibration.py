from __future__ import annotations

import unittest

from photon_fab.service import PhotonService


class CalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PhotonService()
        for user_id, role in (
            ("admin", "admin"),
            ("eng", "engineer"),
            ("op", "operator"),
            ("qa", "quality"),
        ):
            self.service.auth.create_user(user_id, f"pw-{user_id}-long", role)
        self.tokens = {u: self.service.auth.login(u, f"pw-{u}-long") for u in ("admin", "eng", "op", "qa")}
        self.admin = self.tokens["admin"]
        self.service.register_certificate(self.admin, "CERT-1", "spectrometer-1", "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00")
        self.service.create_lot(self.admin, "LOT-1", "sensor", "P1", 5)

    def test_register_versions_and_query(self) -> None:
        first = self.service.get_certificate(self.tokens["op"], "CERT-1")
        self.assertEqual(first["version"], 1)
        self.assertEqual(first["status"], "active")
        second = self.service.register_certificate(self.admin, "CERT-1", "spectrometer-1", "2026-06-01T00:00:00+00:00", "2027-06-01T00:00:00+00:00")
        self.assertEqual(second["version"], 2)
        versions = [row["version"] for row in self.service.list_certificates(self.tokens["qa"], "spectrometer-1")]
        self.assertEqual(versions, [1, 2])

    def test_register_rejects_invalid_window(self) -> None:
        with self.assertRaises(ValueError):
            self.service.register_certificate(self.admin, "CERT-2", "spectrometer-2", "2027-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00")

    def test_verify_certificate_window(self) -> None:
        ok = self.service.verify_certificate(self.tokens["eng"], "spectrometer-1", "2026-09-24T00:00:00+00:00")
        self.assertEqual(ok["certificate_id"], "CERT-1")
        with self.assertRaises(PermissionError):
            self.service.verify_certificate(self.tokens["eng"], "spectrometer-1", "2028-01-01T00:00:00+00:00")
        with self.assertRaises(PermissionError):
            self.service.verify_certificate(self.tokens["eng"], "spectrometer-1", "2025-01-01T00:00:00+00:00")
        with self.assertRaises(PermissionError):
            self.service.verify_certificate(self.tokens["eng"], "unknown-instrument")

    def test_measurement_requires_valid_certificate(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.add_measurement(self.tokens["op"], "LOT-1", 520.0, 0.9, 0.01, "spectrometer-9")
        result = self.service.add_measurement(self.tokens["op"], "LOT-1", 520.0, 0.9, 0.01, "spectrometer-1")
        self.assertEqual(result["certificate_id"], "CERT-1")
        self.assertEqual(result["certificate_version"], 1)

    def test_measurement_blocked_after_revoke_and_history_kept(self) -> None:
        done = self.service.add_measurement(self.tokens["op"], "LOT-1", 520.0, 0.9, 0.01, "spectrometer-1")
        self.service.revoke_certificate(self.admin, "CERT-1", "溯源标准件失效")
        with self.assertRaises(PermissionError):
            self.service.add_measurement(self.tokens["op"], "LOT-1", 650.0, 0.8, 0.01, "spectrometer-1")
        row = self.service.db.execute("SELECT certificate_id,certificate_version FROM measurements WHERE measurement_id=?", (done["measurement_id"],)).fetchone()
        self.assertEqual((row["certificate_id"], row["certificate_version"]), ("CERT-1", 1))

    def test_measurement_blocked_after_expiry(self) -> None:
        self.service.register_certificate(self.admin, "CERT-EXP", "spectrometer-2", "2020-01-01T00:00:00+00:00", "2020-12-31T00:00:00+00:00")
        with self.assertRaises(PermissionError):
            self.service.add_measurement(self.tokens["op"], "LOT-1", 520.0, 0.9, 0.01, "spectrometer-2")

    def test_new_version_does_not_rewrite_history(self) -> None:
        done = self.service.add_measurement(self.tokens["op"], "LOT-1", 520.0, 0.9, 0.01, "spectrometer-1")
        self.service.register_certificate(self.admin, "CERT-1", "spectrometer-1", "2026-01-01T00:00:00+00:00", "2028-01-01T00:00:00+00:00")
        row = self.service.db.execute("SELECT certificate_version FROM measurements WHERE measurement_id=?", (done["measurement_id"],)).fetchone()
        self.assertEqual(row["certificate_version"], 1)
        newer = self.service.add_measurement(self.tokens["op"], "LOT-1", 650.0, 0.8, 0.01, "spectrometer-1")
        self.assertEqual(newer["certificate_version"], 2)

    def test_role_permissions(self) -> None:
        for token in (self.tokens["eng"], self.tokens["op"], self.tokens["qa"]):
            with self.assertRaises(PermissionError):
                self.service.register_certificate(token, "CERT-X", "spectrometer-1", "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00")
            with self.assertRaises(PermissionError):
                self.service.revoke_certificate(token, "CERT-1", "越权撤销")
        # 质量人员和管理员可查看证书审计，其他角色只读
        self.assertTrue(self.service.certificate_audit(self.tokens["qa"], "CERT-1"))
        self.assertTrue(self.service.certificate_audit(self.admin, "CERT-1"))
        for token in (self.tokens["eng"], self.tokens["op"]):
            with self.assertRaises(PermissionError):
                self.service.certificate_audit(token, "CERT-1")
        # 所有角色可读取证书信息
        self.assertEqual(self.service.get_certificate(self.tokens["op"], "CERT-1")["certificate_id"], "CERT-1")

    def test_revoke_requires_reason_and_is_terminal(self) -> None:
        with self.assertRaises(ValueError):
            self.service.revoke_certificate(self.admin, "CERT-1", "  ")
        revoked = self.service.revoke_certificate(self.admin, "CERT-1", "实验室搬迁")
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(revoked["revoked_by"], "admin")
        with self.assertRaises(ValueError):
            self.service.revoke_certificate(self.admin, "CERT-1", "重复撤销")
        with self.assertRaises(KeyError):
            self.service.revoke_certificate(self.admin, "CERT-MISSING", "不存在")
        events = [e["event_type"] for e in self.service.certificate_audit(self.admin, "CERT-1")]
        self.assertEqual(events, ["certificate.registered", "certificate.revoked"])


if __name__ == "__main__":
    unittest.main()
