"""容器和快照检查使用的冒烟验收命令。"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone

from .service import PhotonService


def run() -> dict:
    service = PhotonService()
    service.bootstrap_admin()
    token = service.auth.login("admin", "photon-admin")
    now = datetime.now(timezone.utc)
    service.register_certificate(token, "CERT-SPEC-1", "spectrometer-1", "NIM", (now - timedelta(days=30)).isoformat(), (now + timedelta(days=335)).isoformat())
    service.create_lot(token, "LOT-DEMO", "CMOS image sensor", "P3.2", 10)
    for wavelength, response in ((450, .71), (520, .93), (650, .84)):
        service.add_measurement(token, "LOT-DEMO", wavelength, response, .01, "spectrometer-1")
    validity = service.certificate_validity(token, "spectrometer-1")
    result = service.analyze(token, "LOT-DEMO")
    service.approve(token, "LOT-DEMO", "hold", "awaiting quality review")
    return {"status": "ok", "lot": result["lot_id"], "peak": result["spectrum"]["peak_wavelength_nm"], "events": len(service.audit(token, "LOT-DEMO")), "certificate": {"cert_id": validity["cert_id"], "version": validity["version"]}}


def main() -> None:
    argparse.ArgumentParser().parse_args()
    print(json.dumps(run(), ensure_ascii=False))


if __name__ == "__main__":
    main()
