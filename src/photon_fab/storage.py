"""芯片批次和测量记录的 SQLite 结构及事务辅助函数。"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS chip_lots(
 lot_id TEXT PRIMARY KEY, product TEXT NOT NULL, process_rev TEXT NOT NULL,
 wafer_count INTEGER NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS measurements(
 measurement_id TEXT PRIMARY KEY, lot_id TEXT NOT NULL REFERENCES chip_lots(lot_id),
 wavelength_nm REAL NOT NULL, response REAL NOT NULL, noise REAL NOT NULL,
 instrument TEXT NOT NULL, operator TEXT NOT NULL, measured_at TEXT NOT NULL,
 cert_id TEXT, cert_version INTEGER,
 UNIQUE(lot_id,measurement_id));
CREATE TABLE IF NOT EXISTS calibration_certificates(
 cert_id TEXT NOT NULL, version INTEGER NOT NULL,
 instrument TEXT NOT NULL, issuer TEXT NOT NULL,
 valid_from TEXT NOT NULL, valid_until TEXT NOT NULL,
 registered_by TEXT NOT NULL, registered_at TEXT NOT NULL,
 PRIMARY KEY(cert_id,version));
CREATE TABLE IF NOT EXISTS certificate_revocations(
 cert_id TEXT PRIMARY KEY, reason TEXT NOT NULL,
 revoked_by TEXT NOT NULL, revoked_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certificate_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lot_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, lot_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
 lot_id TEXT NOT NULL, reviewer TEXT NOT NULL, decision TEXT NOT NULL,
 reason TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(lot_id,reviewer));
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(path: str = ":memory:") -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    columns = {row[1] for row in db.execute("PRAGMA table_info(measurements)")}
    if "cert_id" not in columns:
        db.execute("ALTER TABLE measurements ADD COLUMN cert_id TEXT")
        db.execute("ALTER TABLE measurements ADD COLUMN cert_version INTEGER")
    db.commit()
    return db


@contextmanager
def transaction(db: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def event(db: sqlite3.Connection, lot_id: str, event_type: str, actor: str, payload: dict) -> None:
    db.execute("INSERT INTO lot_events(lot_id,event_type,actor,payload,created_at) VALUES(?,?,?,?,?)", (lot_id, event_type, actor, json.dumps(payload, sort_keys=True), utcnow()))


def certificate_event(db: sqlite3.Connection, cert_id: str, event_type: str, actor: str, payload: dict) -> None:
    db.execute("INSERT INTO certificate_events(cert_id,event_type,actor,payload,created_at) VALUES(?,?,?,?,?)", (cert_id, event_type, actor, json.dumps(payload, sort_keys=True), utcnow()))
