from __future__ import annotations

import unittest

from photon_fab.service import PhotonService


class CalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PhotonService()
        self.service.bootstrap_admin()
        self.service.auth.create_user("qual", "quality-pass", "quality")
        self.service.auth.create_user("eng", "engineer-pass", "engineer")
        self.service.auth.create_user("op", "operator-pass", "operator")
        self.admin = self.service.auth.login("admin", "photon-admin")
        self.quality = self.service.auth.login("qual", "quality-pass")
        self.engineer = self.service.auth.login("eng", "engineer-pass")
        self.operator = self.service.auth.login("op", "operator-pass")
        self.service.create_lot(self.engineer, "LOT-1", "sensor", "P1", 5)

    def _register(self, cert_id: str = "CERT-1", instrument: str = "spec-1",
                  valid_from: str = "2020-01-01T00:00:00+00:00",
                  valid_until: str = "2030-01-01T00:00:00+00:00") -> dict:
        return self.service.register_certificate(self.admin, cert_id, instrument, "NIM", valid_from, valid_until)

    def _measure(self) -> dict:
        return self.service.add_measurement(self.operator, "LOT-1", 520.0, 0.9, 0.01, "spec-1")

    def _measurement_rows(self) -> list:
        return self.service.db.execute("SELECT * FROM measurements ORDER BY measured_at").fetchall()

    def test_register_versions_and_validity_query(self) -> None:
        first = self._register()
        self.assertEqual(first["version"], 1)
        self.assertEqual(first["status"], "active")
        second = self._register(valid_until="2031-01-01T00:00:00+00:00")
        self.assertEqual(second["version"], 2)
        self.assertEqual(len(second["versions"]), 2)
        validity = self.service.certificate_validity(self.operator, "spec-1")
        self.assertTrue(validity["valid"])
        self.assertEqual(validity["cert_id"], "CERT-1")
        self.assertEqual(validity["version"], 2)

    def test_validity_query_at_moment(self) -> None:
        self._register(valid_from="2026-01-01T00:00:00+00:00", valid_until="2026-06-30T00:00:00+00:00")
        before = self.service.certificate_validity(self.operator, "spec-1", "2025-06-01T00:00:00+00:00")
        self.assertEqual(before["reason"], "not_yet_valid")
        during = self.service.certificate_validity(self.operator, "spec-1", "2026-03-01T00:00:00+00:00")
        self.assertTrue(during["valid"])
        after = self.service.certificate_validity(self.operator, "spec-1", "2027-01-01T00:00:00+00:00")
        self.assertEqual(after["reason"], "expired")
        unknown = self.service.certificate_validity(self.operator, "spec-x")
        self.assertEqual(unknown["reason"], "no_certificate")

    def test_measurement_requires_certificate(self) -> None:
        with self.assertRaises(ValueError):
            self._measure()
        self.assertEqual(self._measurement_rows(), [])

    def test_expired_certificate_blocks_measurement(self) -> None:
        self._register(valid_until="2020-12-31T00:00:00+00:00")
        with self.assertRaises(ValueError):
            self._measure()
        self.assertEqual(self._measurement_rows(), [])

    def test_revoked_certificate_blocks_measurement(self) -> None:
        self._register()
        self.service.revoke_certificate(self.admin, "CERT-1", "标定数据造假")
        validity = self.service.certificate_validity(self.operator, "spec-1")
        self.assertEqual(validity["reason"], "revoked")
        with self.assertRaises(ValueError):
            self._measure()
        self.assertEqual(self._measurement_rows(), [])

    def test_measurement_records_certificate_version_and_history_is_immutable(self) -> None:
        self._register()
        first = self._measure()
        self.assertEqual((first["cert_id"], first["cert_version"]), ("CERT-1", 1))
        self._register(valid_until="2031-01-01T00:00:00+00:00")
        second = self._measure()
        self.assertEqual((second["cert_id"], second["cert_version"]), ("CERT-1", 2))
        rows = self._measurement_rows()
        self.assertEqual([(r["cert_id"], r["cert_version"]) for r in rows], [("CERT-1", 1), ("CERT-1", 2)])
        versions = self.service.get_certificate(self.operator, "CERT-1")["versions"]
        self.assertEqual([v["version"] for v in versions], [1, 2])
        self.assertEqual(versions[0]["valid_until"], "2030-01-01T00:00:00+00:00")

    def test_revoke_and_replacement_certificate_keep_history(self) -> None:
        self._register()
        self._measure()
        self.service.revoke_certificate(self.admin, "CERT-1", "证书被发证机构撤回")
        self._register(cert_id="CERT-2")
        replacement = self._measure()
        self.assertEqual(replacement["cert_id"], "CERT-2")
        rows = self._measurement_rows()
        self.assertEqual([r["cert_id"] for r in rows], ["CERT-1", "CERT-2"])
        self.assertEqual(self.service.get_certificate(self.operator, "CERT-1")["status"], "revoked")

    def test_revoke_validation(self) -> None:
        self._register()
        with self.assertRaises(KeyError):
            self.service.revoke_certificate(self.admin, "CERT-X", "不存在")
        with self.assertRaises(ValueError):
            self.service.revoke_certificate(self.admin, "CERT-1", "  ")
        self.service.revoke_certificate(self.admin, "CERT-1", "超期未校")
        with self.assertRaises(ValueError):
            self.service.revoke_certificate(self.admin, "CERT-1", "重复撤销")
        with self.assertRaises(ValueError):
            self._register()

    def test_certificate_registration_validation(self) -> None:
        with self.assertRaises(ValueError):
            self._register(valid_from="2030-01-01T00:00:00+00:00", valid_until="2020-01-01T00:00:00+00:00")
        with self.assertRaises(ValueError):
            self._register(valid_from="not-a-time")
        with self.assertRaises(ValueError):
            self.service.register_certificate(self.admin, " ", "spec-1", "NIM", "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00")

    def test_role_permissions(self) -> None:
        for token in (self.operator, self.engineer, self.quality):
            with self.assertRaises(PermissionError):
                self.service.register_certificate(token, "CERT-9", "spec-1", "NIM", "2020-01-01T00:00:00+00:00", "2030-01-01T00:00:00+00:00")
        self._register()
        for token in (self.operator, self.engineer, self.quality):
            with self.assertRaises(PermissionError):
                self.service.revoke_certificate(token, "CERT-1", "越权")
            self.assertTrue(self.service.certificate_validity(token, "spec-1")["valid"])
            self.assertEqual(self.service.get_certificate(token, "CERT-1")["cert_id"], "CERT-1")

    def test_audit_visibility_and_trail(self) -> None:
        self._register()
        self.service.revoke_certificate(self.admin, "CERT-1", "溯源链断裂")
        for token in (self.operator, self.engineer):
            with self.assertRaises(PermissionError):
                self.service.certificate_audit(token, "CERT-1")
        for token in (self.quality, self.admin):
            events = self.service.certificate_audit(token, "CERT-1")
            self.assertEqual([e["event_type"] for e in events], ["registered", "revoked"])
            self.assertEqual(events[1]["actor"], "admin")


if __name__ == "__main__":
    unittest.main()
