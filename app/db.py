"""
Tripwire storage layer.

Everything the dashboard shows and everything you'd cite in the
"attack trail" comes out of these two tables:

- sessions: one row per agent session, tracks whether it's been frozen
- events:   one row per tool call (legit or canary), in order, so you
            can reconstruct the exact sequence that led to a trigger
"""
import sqlite3
import time
import json
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "tripwire.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                created_at REAL,
                frozen INTEGER DEFAULT 0,
                frozen_at REAL,
                frozen_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                ts REAL,
                event_type TEXT,       -- 'tool_call' | 'canary_trigger' | 'freeze'
                tool_name TEXT,
                arguments TEXT,        -- JSON string
                is_canary INTEGER DEFAULT 0
            );
            """
        )


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def ensure_session(session_id: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO sessions (session_id, created_at) VALUES (?, ?)",
            (session_id, time.time()),
        )


def log_event(session_id: str, event_type: str, tool_name: str, arguments: dict, is_canary: bool):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO events (session_id, ts, event_type, tool_name, arguments, is_canary)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, time.time(), event_type, tool_name, json.dumps(arguments), int(is_canary)),
        )


def freeze_session(session_id: str, reason: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE sessions SET frozen = 1, frozen_at = ?, frozen_reason = ? WHERE session_id = ?",
            (time.time(), reason, session_id),
        )
        conn.execute(
            "INSERT INTO events (session_id, ts, event_type, tool_name, arguments, is_canary) "
            "VALUES (?, ?, 'freeze', NULL, ?, 0)",
            (session_id, time.time(), json.dumps({"reason": reason})),
        )


def is_frozen(session_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT frozen FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return bool(row and row["frozen"])


def get_trail(session_id: str):
    """Full ordered event history for a session — this IS your 'attack trail'."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY ts ASC", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_events(limit: int = 200):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
