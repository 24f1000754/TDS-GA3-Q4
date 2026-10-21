import hashlib
import json
import os
import sqlite3
from typing import Any

DB_PATH = os.environ.get("INCIDENT_DB_PATH", "incident_agent.sqlite3")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                request_json TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                PRIMARY KEY (run_id, receipt_id)
            )
        """)


def get_run(run_id: str):
    with connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None


def create_run(run_id: str, request_hash: str, request_json: str, state_json: str):
    with connect() as conn:
        conn.execute(
            "INSERT INTO runs(run_id, request_hash, request_json, state_json) VALUES(?,?,?,?)",
            (run_id, request_hash, request_json, state_json),
        )


def save_state(run_id: str, state: dict):
    with connect() as conn:
        conn.execute(
            "UPDATE runs SET state_json=?, updated_at=CURRENT_TIMESTAMP WHERE run_id=?",
            (canonical_json(state), run_id),
        )


def get_receipt(run_id: str, receipt_id: str):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM receipts WHERE run_id=? AND receipt_id=?", (run_id, receipt_id)
        ).fetchone()
        return dict(row) if row else None


def save_receipt(run_id: str, receipt_id: str, receipt_hash: str, response_json: str):
    with connect() as conn:
        conn.execute(
            "INSERT INTO receipts(run_id, receipt_id, receipt_hash, response_json) VALUES(?,?,?,?)",
            (run_id, receipt_id, receipt_hash, response_json),
        )
