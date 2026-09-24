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
 certificate_id TEXT, certificate_version INTEGER,
 UNIQUE(lot_id,measurement_id));
CREATE TABLE IF NOT EXISTS calibration_certificates(
 certificate_id TEXT NOT NULL, version INTEGER NOT NULL,
 instrument TEXT NOT NULL, issued_at TEXT NOT NULL,
 valid_from TEXT NOT NULL, valid_until TEXT NOT NULL,
 status TEXT NOT NULL, registered_by TEXT NOT NULL,
 revoked_at TEXT, revoked_by TEXT, revoke_reason TEXT,
 PRIMARY KEY(certificate_id,version));
CREATE TABLE IF NOT EXISTS certificate_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, certificate_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lot_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, lot_id TEXT NOT NULL,
 event_type TEXT NOT NULL, actor TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(
 lot_id TEXT NOT NULL, reviewer TEXT NOT NULL, decision TEXT NOT NULL,
 reason TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(lot_id,reviewer));
"""

# 早于证书功能版本创建的数据库需要补齐测量表的证书快照列；
# 历史测量行允许为 NULL，新测量必须携带证书版本。
_MEASUREMENT_MIGRATIONS = ("certificate_id TEXT", "certificate_version INTEGER")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(path: str = ":memory:") -> sqlite3.Connection:
    # HTTP 服务在工作线程中处理请求，连接需允许跨线程使用；
    # 写路径均由 BEGIN IMMEDIATE 事务串行化。
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    existing = {row[1] for row in db.execute("PRAGMA table_info(measurements)")}
    for column in _MEASUREMENT_MIGRATIONS:
        name = column.split()[0]
        if name not in existing:
            db.execute(f"ALTER TABLE measurements ADD COLUMN {column}")
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


def certificate_event(db: sqlite3.Connection, certificate_id: str, event_type: str, actor: str, payload: dict) -> None:
    db.execute("INSERT INTO certificate_events(certificate_id,event_type,actor,payload,created_at) VALUES(?,?,?,?,?)", (certificate_id, event_type, actor, json.dumps(payload, sort_keys=True), utcnow()))
