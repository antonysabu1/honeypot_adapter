"""Unit tests for shared/storage.py.

Verifies schema creation, column migrations, session lifecycle, event
insertion with correct last_seen/request_count updates, and the DB_FILE
redirect that tests rely on.
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import shared.storage as storage_mod
from shared.storage import StorageEngine


def _tmp_engine() -> StorageEngine:
    tmp = Path(tempfile.mkdtemp(prefix="honeypot-storage-test-"))
    return StorageEngine(tmp / "test.db")


def test_schema_created():
    se = _tmp_engine()
    tables = {r[0] for r in se._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    for expected in ("sessions", "events", "authentication_attempts", "commands", "attack_techniques"):
        assert expected in tables, f"table {expected!r} missing"
    se._close()
    print("PASS test_schema_created")


def test_new_columns_present():
    se = _tmp_engine()
    cols = {r[1] for r in se._conn.execute("PRAGMA table_info(sessions)").fetchall()}
    for expected in ("last_seen", "request_count", "distinct_actions"):
        assert expected in cols, f"column {expected!r} missing from sessions"
    se._close()
    print("PASS test_new_columns_present")


def test_migration_adds_columns_to_old_db():
    """Simulates an existing DB that lacks last_seen/request_count."""
    tmp = Path(tempfile.mkdtemp(prefix="honeypot-migrate-test-"))
    db_path = tmp / "old.db"
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL,
        protocol TEXT NOT NULL, started_at TEXT NOT NULL,
        closed_at TEXT, duration_ms INTEGER,
        username TEXT DEFAULT 'root',
        session_source TEXT DEFAULT 'protocol_native', cwd TEXT DEFAULT '/'
    )""")
    conn.commit()
    conn.close()

    se = StorageEngine(db_path)
    cols = {r[1] for r in se._conn.execute("PRAGMA table_info(sessions)").fetchall()}
    for expected in ("last_seen", "request_count", "distinct_actions"):
        assert expected in cols, f"migration did not add {expected!r}"
    se._close()
    print("PASS test_migration_adds_columns_to_old_db")


def test_upsert_and_close_session():
    se = _tmp_engine()
    se.upsert_session("s1", "1.2.3.4", "ssh", username="bob")
    row = se.fetch_one("SELECT * FROM sessions WHERE session_id='s1'")
    assert row is not None
    assert row["source_ip"] == "1.2.3.4"
    assert row["username"] == "bob"
    assert row["closed_at"] is None

    se.close_session("s1")
    row = se.fetch_one("SELECT * FROM sessions WHERE session_id='s1'")
    assert row["closed_at"] is not None
    se._close()
    print("PASS test_upsert_and_close_session")


def test_insert_event_updates_last_seen_and_request_count():
    se = _tmp_engine()
    se.upsert_session("s2", "10.0.0.1", "telnet")
    se.insert_event(session_id="s2", protocol="telnet", action="whoami", response_type="command_output", status="0")
    se.insert_event(session_id="s2", protocol="telnet", action="id", response_type="command_output", status="0")
    row = se.fetch_one("SELECT last_seen, request_count FROM sessions WHERE session_id='s2'")
    assert row["last_seen"] is not None, "last_seen not updated"
    assert row["request_count"] == 2, f"request_count expected 2 got {row['request_count']}"
    se._close()
    print("PASS test_insert_event_updates_last_seen_and_request_count")


def test_no_duplicate_unique_constraint_on_attack_techniques():
    se = _tmp_engine()
    se.upsert_technique("T1033", "System Owner/User Discovery", "Discovery")
    se.upsert_technique("T1033", "System Owner/User Discovery", "Discovery")
    rows = se.fetch_all("SELECT * FROM attack_techniques WHERE technique_id='T1033'")
    assert len(rows) == 1, f"expected 1 row, got {len(rows)}"
    se._close()
    print("PASS test_no_duplicate_unique_constraint_on_attack_techniques")


def test_db_file_override():
    tmp = Path(tempfile.mkdtemp(prefix="honeypot-dbfile-test-"))
    old_db_file = storage_mod.DB_FILE
    old_storage = storage_mod._storage
    try:
        storage_mod.close_storage()
        storage_mod.DB_FILE = tmp / "override.db"
        se = storage_mod.get_storage()
        assert se._db_path == tmp / "override.db", f"wrong path: {se._db_path}"
        print("PASS test_db_file_override")
    finally:
        storage_mod.close_storage()
        storage_mod.DB_FILE = old_db_file
        storage_mod._storage = old_storage


def main():
    test_schema_created()
    test_new_columns_present()
    test_migration_adds_columns_to_old_db()
    test_upsert_and_close_session()
    test_insert_event_updates_last_seen_and_request_count()
    test_no_duplicate_unique_constraint_on_attack_techniques()
    test_db_file_override()
    print("\nALL STORAGE TESTS PASSED")


if __name__ == "__main__":
    main()
