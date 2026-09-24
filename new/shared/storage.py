"""Persistent SQLite storage for honeypot telemetry.

Replaces flat JSONL append-only logging with a proper database:
- Sessions table: track active/closed sessions
- Events table: store every telemetry event
- Authentication attempts: username/password/fingerprint attempts
- Commands: command name, args, exit code, timing
- Attack techniques: MITRE ATT&CK tagging per event

Provides a query API for the future AI engine while remaining
backward-compatible with JSONL export for existing tooling.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "logs" / "honeypot.db"
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
JSONL_PATH = LOG_DIR / "honeypot.jsonl"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    source_ip    TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    closed_at    TEXT,
    duration_ms  INTEGER,
    username     TEXT DEFAULT 'root',
    session_source TEXT DEFAULT 'protocol_native',
    cwd           TEXT DEFAULT '/'
);

CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    action       TEXT NOT NULL,
    parameters   TEXT,
    response_type TEXT NOT NULL,
    status       TEXT NOT NULL,
    mitre_attack_id TEXT,
    mitre_technique_name TEXT,
    mitre_tactic   TEXT,
    mitre_confidence INTEGER DEFAULT 0,
    mitre_attack_id_secondary TEXT,
    mitre_technique_name_secondary TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE TABLE IF NOT EXISTS authentication_attempts (
    attempt_id   TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    session_id   TEXT,
    protocol     TEXT NOT NULL,
    source_ip    TEXT,
    username     TEXT,
    password     TEXT,
    success      INTEGER NOT NULL DEFAULT 0,
    mitre_attack_id TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE TABLE IF NOT EXISTS commands (
    command_id   TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    action       TEXT NOT NULL,
    args         TEXT,
    cwd          TEXT,
    exit_code    INTEGER NOT NULL DEFAULT 0,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    response_type TEXT NOT NULL,
    status       TEXT NOT NULL,
    mitre_attack_id TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    description  TEXT,
    sessions     INTEGER NOT NULL DEFAULT 1,
    events       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (technique_id, sessions)
);
"""

# ── Helpers ────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


# ── Engine ───────────────────────────────────────────────────────────────────

class StorageEngine:
    """SQLite-backed telemetry store."""

    def __init__(self, db_path: str | Path = DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._open()

    # ── lifecycle ────────────────────────────────────────────────────────

    def _open(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        # Migrate: copy existing JSONL → SQLite if DB was just created
        self._migrate_jsonl()

    def _close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _migrate_jsonl(self) -> None:
        """Best-effort import of existing JSONL into SQLite."""
        if not JSONL_PATH.exists():
            return
        try:
            with open(JSONL_PATH, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        # Minimal fields; missing ones stay NULL
                        eid = e.get("event_id") or _uuid()
                        ts = e.get("timestamp") or _now_iso()
                        sid = e.get("session_id") or ""
                        proto = e.get("protocol") or ""
                        action = e.get("action") or ""
                        params = json.dumps(e.get("parameters", {})) or None
                        rtype = e.get("response_type") or ""
                        status = e.get("response_status") or "0"
                        mitre = e.get("mitre_attack_id")
                        mitre_name = e.get("mitre_technique_name")
                        mitre_tactic = e.get("mitre_tactic")
                        mitre_sec = e.get("mitre_technique_name_secondary")
                        self._conn.execute(
                            """INSERT OR IGNORE INTO events
                               (event_id, timestamp, session_id, protocol, action,
                                parameters, response_type, status,
                                mitre_attack_id, mitre_technique_name,
                                mitre_tactic, mitre_technique_name_secondary)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (eid, ts, sid, proto, action, params, rtype, status,
                             mitre, mitre_name, mitre_tactic, mitre_sec),
                        )
                    except (json.JSONDecodeError, KeyError):
                        continue
            self._conn.commit()
        except Exception:
            pass  # migration is best-effort; do not break startup

    # ── context manager ────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self._close()

    # ── sessions ───────────────────────────────────────────────────────────

    def upsert_session(
        self,
        session_id: str,
        source_ip: str,
        protocol: str,
        username: str = "root",
        session_source: str = "protocol_native",
        cwd: str = "/",
    ) -> None:
        self._conn.execute(
            """INSERT INTO sessions
               (session_id, source_ip, protocol, started_at, username,
                session_source, cwd)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET
                 source_ip=excluded.source_ip,
                 protocol=excluded.protocol,
                 username=excluded.username,
                 session_source=excluded.session_source,
                 cwd=excluded.cwd,
                 closed_at=NULL,
                 duration_ms=NULL""",
            (session_id, source_ip, protocol, _now_iso(), username,
             session_source, cwd),
        )
        self._conn.commit()

    def close_session(self, session_id: str, duration_ms: int | None = None) -> None:
        self._conn.execute(
            "UPDATE sessions SET closed_at=?, duration_ms=? WHERE session_id=?",
            (_now_iso(), duration_ms, session_id),
        )
        self._conn.commit()

    # ── events ─────────────────────────────────────────────────────────────

    def insert_event(
        self,
        event_id: str | None = None,
        session_id: str | None = None,
        protocol: str = "ssh",
        action: str = "",
        parameters: dict | None = None,
        response_type: str = "command_output",
        status: str = "0",
        mitre_attack_id: str | None = None,
        mitre_technique_name: str | None = None,
        mitre_tactic: str | None = None,
        mitre_technique_name_secondary: str | None = None,
    ) -> str:
        eid = event_id or _uuid()
        ts = _now_iso()
        self._conn.execute(
            """INSERT OR IGNORE INTO events
               (event_id, timestamp, session_id, protocol, action,
                parameters, response_type, status,
                mitre_attack_id, mitre_technique_name,
                mitre_tactic, mitre_technique_name_secondary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (eid, ts, session_id, protocol, action,
             json.dumps(parameters) if parameters else None,
             response_type, status,
             mitre_attack_id, mitre_technique_name, mitre_tactic,
             mitre_technique_name_secondary),
        )
        # Update session start/end via the owning session
        if session_id:
            self._conn.execute(
                "UPDATE sessions SET started_at=? WHERE session_id=?",
                (ts, session_id),
            )
        self._conn.commit()
        return eid

    # ── authentication_attempts ────────────────────────────────────────────

    def insert_auth_attempt(
        self,
        attempt_id: str | None = None,
        session_id: str | None = None,
        protocol: str = "ssh",
        source_ip: str | None = None,
        username: str | None = None,
        password: str | None = None,
        success: int = 0,
        mitre_attack_id: str | None = None,
    ) -> str:
        aid = attempt_id or _uuid()
        ts = _now_iso()
        self._conn.execute(
            """INSERT OR IGNORE INTO authentication_attempts
               (attempt_id, timestamp, session_id, protocol, source_ip,
                username, password, success, mitre_attack_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (aid, ts, session_id, protocol, source_ip, username, password,
             int(success), mitre_attack_id),
        )
        if session_id:
            self._conn.execute(
                "UPDATE sessions SET username=? WHERE session_id=?",
                (username or "unknown", session_id),
            )
        self._conn.commit()
        return aid

    # ── commands ───────────────────────────────────────────────────────────

    def insert_command(
        self,
        command_id: str | None = None,
        session_id: str | None = None,
        protocol: str = "ssh",
        action: str = "",
        args: list | None = None,
        cwd: str | None = None,
        exit_code: int = 0,
        duration_ms: int = 0,
        response_type: str = "command_output",
        status: str = "0",
        mitre_attack_id: str | None = None,
    ) -> str:
        cid = command_id or _uuid()
        ts = _now_iso()
        a_str = json.dumps(args) if args else None
        self._conn.execute(
            """INSERT OR IGNORE INTO commands
               (command_id, timestamp, session_id, protocol, action,
                args, cwd, exit_code, duration_ms,
                response_type, status, mitre_attack_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cid, ts, session_id, protocol, action, a_str, cwd,
             exit_code, duration_ms, response_type, status, mitre_attack_id),
        )
        self._conn.commit()
        return cid

    # ── attack_techniques ──────────────────────────────────────────────────

    def upsert_technique(
        self,
        technique_id: str,
        name: str,
        tactic: str,
        description: str | None = None,
    ) -> None:
        self._conn.execute(
            """INSERT INTO attack_techniques (technique_id, name, tactic, description, sessions, events)
               VALUES (?, ?, ?, ?, 1, 1)
               ON CONFLICT(technique_id) DO UPDATE SET
                 name=excluded.name,
                 tactic=excluded.tactic,
                 description=excluded.description,
                 sessions=sessions + 1,
                 events = events + 1""",
            (technique_id, name, tactic, description),
        )
        self._conn.commit()

    # ── query helpers ──────────────────────────────────────────────────────

    def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self._conn.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def fetch_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.fetch_all(sql, params)
        return rows[0] if rows else None

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        sql = f"SELECT COUNT(*) FROM {table}"
        if where:
            sql += f" WHERE {where}"
        return self._conn.execute(sql, params).fetchone()[0]

    # ── JSONL export ───────────────────────────────────────────────────────

    def export_jsonl(self, path: str | Path | None = None) -> None:
        """Export all events to JSONL for backward compatibility."""
        out = Path(path) if path else JSONL_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        rows = self.fetch_all("SELECT * FROM events")
        with open(out, "w", encoding="utf-8") as f:
            for row in rows:
                # Build a clean dict without the SQL rowid
                d = {k: v for k, v in row.items() if v is not None}
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

    # ── retention / rotation ───────────────────────────────────────────────

    def prune_old_sessions(self, days: int = 90) -> int:
        """Remove sessions and associated data older than *days*."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        # Delete orphan events first (FK cascade handles it with ON DELETE)
        self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self._conn.execute(
            "DELETE FROM sessions WHERE started_at < ?", (cutoff,)
        )
        self._conn.commit()
        return self._conn.total_changes


# ── Global instance ──────────────────────────────────────────────────────────

_storage: StorageEngine | None = None


def get_storage() -> StorageEngine:
    """Return the global storage engine (lazy initialisation)."""
    global _storage
    if _storage is None:
        _storage = StorageEngine()
    return _storage


def init_storage(db_path: str | Path | None = None) -> StorageEngine:
    """Explicitly initialise the storage engine."""
    global _storage
    _storage = StorageEngine(db_path)
    return _storage


def close_storage() -> None:
    global _storage
    if _storage:
        _storage._close()
        _storage = None