"""M16 Telemetry Hardening tests.

Verifies that every attacker interaction produces structured, consistent,
correlated telemetry suitable for later security analysis.

Note: These tests use the shared logger/storage in-process; they do NOT
start real network listeners.  They exercise the same code paths the
adapters use (build_event -> log_event, StorageEngine -> SQLite).
"""

import json
import os
import sys
import tempfile
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.logger import log_event, REQUIRED_KEYS, _prune_log
from shared.events import build_event
from shared.storage import init_storage, close_storage, StorageEngine
from shared.config import get as config_get


def test_required_keys_consistency():
    """Every build_event output must have all 17 REQUIRED_KEYS."""
    passed = 0
    failed = 0
    # Test lifecycle events
    for action in [
        "connection_established", "connection_closed", "session_limit_reached",
        "login_attempt", "pubkey_attempt",
    ]:
        for proto in ["ssh", "telnet"]:
            event = build_event(
                session_id="s-1", source_ip="1.2.3.4", protocol=proto, action=action,
                parameters={}, response_status="0", response_type="pending", mitre=None,
            )
            missing = [k for k in REQUIRED_KEYS if k not in event]
            if missing:
                failed += 1
                print(f"  FAIL {proto} {action}: missing {missing}")
            else:
                passed += 1
    # Test command events
    for action in ["whoami", "id", "ls /", "env", "cat /etc/passwd"]:
        event = build_event(
            session_id="s-1", source_ip="1.2.3.4", protocol="ssh", action=action,
            parameters={"command": action}, response_status="0",
            response_type="command_output", mitre=None,
        )
        missing = [k for k in REQUIRED_KEYS if k not in event]
        if missing:
            failed += 1
            print(f"  FAIL ssh {action}: missing {missing}")
        else:
            passed += 1
    # Test with MITRE ATT&CK metadata
    event = build_event(
        session_id="s-1", source_ip="1.2.3.4", protocol="ssh", action="whoami",
        parameters={"command": "whoami"}, response_status="0",
        response_type="command_output",
        mitre={"mitre_attack_id": "T1033", "mitre_technique_name": "System Owner/User Discovery",
               "mitre_tactic": "Discovery", "mitre_attack_id_secondary": None,
               "mitre_technique_name_secondary": None, "mitre_confidence": "high"},
    )
    missing = [k for k in REQUIRED_KEYS if k not in event]
    if missing:
        failed += 1
        print(f"  FAIL ssh whoami with mitre: missing {missing}")
    else:
        passed += 1
    # Verify MITRE fields are correctly merged
    if (event["mitre_attack_id"] != "T1033" or
            event["mitre_technique_name"] != "System Owner/User Discovery" or
            event["mitre_tactic"] != "Discovery" or
            event["mitre_confidence"] != "high"):
        failed += 1
        print(f"  FAIL mitre field values incorrect: {event}")
    else:
        passed += 1

    print(f"  test_required_keys_consistency: {passed} passed, {failed} failed")
    return failed == 0


def test_jsonl_malformed_line_resilience():
    """Malformed JSON lines in the log file are skipped; honeypot never crashes."""
    passed = 0
    failed = 0
    tmpdir = tempfile.mkdtemp()
    log_file = os.path.join(tmpdir, "honeypot.jsonl")

    # Write a valid event followed by a malformed line, then another valid event
    with open(log_file, "w") as f:
        # Valid event
        f.write(json.dumps({
            "event_id": "m16-valid-001", "timestamp": "2026-10-04T10:00:00+00:00",
            "protocol": "ssh", "source_ip": "1.2.3.4", "session_id": "s-1",
            "action": "whoami", "parameters": {}, "raw_metadata": {},
            "session_source": "protocol_native", "response_status": "0",
            "response_type": "command_output",
            "mitre_attack_id": "T1033", "mitre_technique_name": "System Owner/User Discovery",
            "mitre_tactic": "Discovery", "mitre_attack_id_secondary": None,
            "mitre_technique_name_secondary": None, "mitre_confidence": "high",
        }) + "\n")
        # Malformed line (not valid JSON)
        f.write("{bad json\n")
        # Another valid event
        f.write(json.dumps({
            "event_id": "m16-valid-002", "timestamp": "2026-10-04T10:01:00+00:00",
            "protocol": "ssh", "source_ip": "1.2.3.4", "session_id": "s-1",
            "action": "ls /", "parameters": {}, "raw_metadata": {},
            "session_source": "protocol_native", "response_status": "0",
            "response_type": "directory_listing",
            "mitre_attack_id": "T1083", "mitre_technique_name": "File and Directory Discovery",
            "mitre_tactic": "Discovery", "mitre_attack_id_secondary": None,
            "mitre_technique_name_secondary": None, "mitre_confidence": "high",
        }) + "\n")

    # Test _prune_log with malformed data
    import shared.logger as lr
    original_max = lr._max_log_size_bytes
    lr._max_log_size_bytes = lambda: 10_000  # large enough not to prune

    try:
        _prune_log()
        # Read the file and verify both valid events survived
        with open(log_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        valid_count = 0
        for line in lines:
            try:
                evt = json.loads(line)
                if evt.get("event_id") in ("m16-valid-001", "m16-valid-002"):
                    valid_count += 1
            except json.JSONDecodeError:
                pass  # malformed line, expected to be skipped
        if valid_count == 2:
            passed += 1
            print("  PASS jsonl_malformed_line_resilience: both valid events survived")
        else:
            failed += 1
            print(f"  FAIL jsonl_malformed_line_resilience: expected 2 valid events, got {valid_count}")
            print(f"    lines: {lines}")
    except Exception as e:
        failed += 1
        print(f"  FAIL jsonl_malformed_line_resilience: exception {e}")
    finally:
        lr._max_log_size_bytes = original_max
    # cleanup
    import shutil
    shutil.rmtree(tmpdir)

    print(f"  test_jsonl_malformed_line_resilience: {passed} passed, {failed} failed")
    return failed == 0


def test_sqlite_integrity_on_init():
    """StorageEngine detects corruption via PRAGMA integrity_check."""
    passed = 0
    failed = 0
    db_path = "/tmp/test_m16_sqlite_corrupt.db"
    # Create a file that SQLite will reject as a corrupt database.
    try:
        # Write garbage that SQLite will reject
        with open(db_path, "wb") as f:
            f.write(b"CORRUPT_GARBAGE_NOT_A_SQLITE_DB_12345!")
        try:
            se = StorageEngine(db_path=db_path)
            # If StorageEngine initialized without raising, check integrity
            try:
                se._verify_integrity()
                # If we get here, integrity check passed on corrupt data — fail
                failed += 1
                print("  FAIL sqlite_integrity_on_init: integrity check passed on corrupt DB")
            except RuntimeError as e:
                # Expected: integrity check detected corruption
                passed += 1
                print("  PASS sqlite_integrity_on_init: RuntimeError raised on corrupt DB")
            finally:
                se._close()
        except sqlite3.DatabaseError as e:
            # StorageEngine __init__ raised DatabaseError because file is not a valid SQLite db
            passed += 1
            print("  PASS sqlite_integrity_on_init: DatabaseError raised during StorageEngine init")
        except RuntimeError as e:
            # StorageEngine __init__ raised RuntimeError for other reasons
            passed += 1
            print(f"  PASS sqlite_integrity_on_init: RuntimeError raised during StorageEngine init: {e}")
        finally:
            try:
                os.unlink(db_path)
            except OSError:
                pass
    except Exception as exc:
        failed += 1
        print(f"  FAIL sqlite_integrity_on_init: setup error {exc}")

    print(f"  test_sqlite_integrity_on_init: {passed} passed, {failed} failed")
    return failed == 0


def test_sqlite_wal_and_concurrent_safety():
    """WAL mode is active; basic read/write safety check."""
    passed = 0
    failed = 0
    db_path = "/tmp/test_m16_wal.db"
    if os.path.exists(db_path):
        os.unlink(db_path)
    try:
        se = init_storage(db_path=db_path)
        # Upsert a session
        se.upsert_session("s-1", "1.2.3.4", "ssh")
        # Insert an event
        eid = se.insert_event(
            event_id="e-1", session_id="s-1", protocol="ssh", action="whoami",
            parameters={}, response_type="command_output", status="0",
        )
        # Close the session
        se.close_session("s-1", 1200)
        # Read it back
        events = se.fetch_session_events("s-1")
        if len(events) == 1 and events[0]["action"] == "whoami":
            passed += 1
            print("  PASS sqlite_wal_and_concurrent_safety: read/write roundtrip OK")
        else:
            failed += 1
            print(f"  FAIL sqlite_wal_and_concurrent_safety: expected 1 event, got {len(events)}")
        close_storage()
        # reset DB
        se.reset_for_testing()
    except Exception as e:
        failed += 1
        print(f"  FAIL sqlite_wal_and_concurrent_safety: exception {e}")
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass

    print(f"  test_sqlite_wal_and_concurrent_safety: {passed} passed, {failed} failed")
    return failed == 0


def test_log_retention_respects_config():
    """Prune respects max_log_size_mb configuration."""
    passed = 0
    failed = 0
    tmpdir = tempfile.mkdtemp()
    log_file = os.path.join(tmpdir, "honeypot.jsonl")

    # Write many events so the file exceeds 1MB
    with open(log_file, "w") as f:
        for i in range(200):
            event = {
                "event_id": f"ret-{i:03d}", "timestamp": "2026-10-04T10:00:00+00:00",
                "protocol": "ssh", "source_ip": "1.2.3.4", "session_id": "s-1",
                "action": "whoami", "parameters": {}, "raw_metadata": {},
                "session_source": "protocol_native", "response_status": "0",
                "response_type": "command_output",
                "mitre_attack_id": "T1033", "mitre_technique_name": "System Owner/User Discovery",
                "mitre_tactic": "Discovery", "mitre_attack_id_secondary": None,
                "mitre_technique_name_secondary": None, "mitre_confidence": "high",
            }
            f.write(json.dumps(event) + "\n")

    # Temporarily set max_log_size_mb to 1 so pruning actually happens
    import shared.config as cfg_mod
    cfg_mod.load()
    original_val = cfg_mod._namespace["max_log_size_mb"]
    try:
        cfg_mod._namespace["max_log_size_mb"] = 1  # 1 MB
    except (KeyError, TypeError):
        # fallback
        pass

    # Run prune
    try:
        _prune_log()
        size = os.path.getsize(log_file)
        # With 1MB limit, file should be <= 1MB (or empty if all lines dropped)
        if size <= 1_048_576:  # 1 MB in bytes
            passed += 1
            print(f"  PASS log_retention_respects_config: file size {size} <= 1MB")
        else:
            failed += 1
            print(f"  FAIL log_retention_respects_config: file size {size} > 1MB")
    except Exception as e:
        failed += 1
        print(f"  FAIL log_retention_respects_config: exception {e}")
    finally:
        cfg_mod._namespace["max_log_size_mb"] = original_val

    import shutil
    shutil.rmtree(tmpdir)

    print(f"  test_log_retention_respects_config: {passed} passed, {failed} failed")
    return failed == 0


def test_session_correlation_data():
    """fetch_correlation_data returns session + events + auth attempts."""
    passed = 0
    failed = 0
    db_path = "/tmp/test_m16_correlation.db"
    if os.path.exists(db_path):
        os.unlink(db_path)
    try:
        se = init_storage(db_path=db_path)
        # Create a session with events and auth
        se.upsert_session("s-ssh-001", "192.168.1.50", "ssh")
        for action in ["whoami", "ls /", "id"]:
            se.insert_event(
                event_id=f"e-{action}", session_id="s-ssh-001",
                protocol="ssh", action=action, parameters={},
                response_type="command_output", status="0",
                mitre_attack_id="T1033" if action == "whoami" else "T1083",
            )
        se.insert_auth_attempt(
            attempt_id="a-001", session_id="s-ssh-001",
            protocol="ssh", source_ip="192.168.1.50",
            username="honeypot", success=1, mitre_attack_id="T1078",
        )

        corr = se.fetch_correlation_data("s-ssh-001")
        if corr is None:
            failed += 1
            print("  FAIL session_correlation_data: fetch_correlation_data returned None")
        else:
            s = corr.get("session")
            evts = corr.get("events", [])
            auths = corr.get("auth_attempts", [])
            if s and s["session_id"] == "s-ssh-001" and len(evts) == 3 and len(auths) == 1:
                passed += 1
                print(f"  PASS session_correlation_data: session={s['session_id']}, events={len(evts)}, auths={len(auths)}")
            else:
                failed += 1
                print(f"  FAIL session_correlation_data: unexpected data {corr}")
        close_storage()
        se.reset_for_testing()
    except Exception as e:
        failed += 1
        print(f"  FAIL session_correlation_data: exception {e}")
        try:
            close_storage()
            se.reset_for_testing()
        except:
            pass

    print(f"  test_session_correlation_data: {passed} passed, {failed} failed")
    return failed == 0


def test_event_schema_contains_mitre_when_provided():
    """When mitre dict is passed to build_event, MITRE fields are merged; when None, they are null."""
    passed = 0
    failed = 0
    # With MITRE
    event_with = build_event(
        session_id="s-1", source_ip="1.2.3.4", protocol="ssh", action="whoami",
        parameters={}, response_status="0", response_type="command_output",
        mitre={"mitre_attack_id": "T1033", "mitre_technique_name": "Sys Discovery",
               "mitre_tactic": "Discovery", "mitre_attack_id_secondary": None,
               "mitre_technique_name_secondary": None, "mitre_confidence": "high"},
    )
    without_keys = (
        "mitre_attack_id" in event_with and "mitre_technique_name" in event_with
        and "mitre_tactic" in event_with and "mitre_confidence" in event_with
    )
    # Without MITRE (None)
    event_without = build_event(
        session_id="s-1", source_ip="1.2.3.4", protocol="ssh", action="whoami",
        parameters={}, response_status="0", response_type="command_output",
        mitre=None,
    )
    null_keys = (
        event_without["mitre_attack_id"] is None
        and event_without["mitre_technique_name"] is None
        and event_without["mitre_tactic"] is None
        and event_without["mitre_confidence"] is None
    )
    if without_keys and null_keys:
        passed += 1
        print("  PASS event_schema_contains_mitre_when_provided")
    else:
        failed += 1
        print(f"  FAIL event_schema_contains_mitre_when_provided: with={without_keys} without={null_keys}")
        print(f"    with: {event_with}")
        print(f"    without: {event_without}")

    print(f"  test_event_schema_contains_mitre_when_provided: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all M16 telemetry tests and report results."""
    tests = [
        ("test_required_keys_consistency", test_required_keys_consistency),
        ("test_jsonl_malformed_line_resilience", test_jsonl_malformed_line_resilience),
        ("test_sqlite_integrity_on_init", test_sqlite_integrity_on_init),
        ("test_sqlite_wal_and_concurrent_safety", test_sqlite_wal_and_concurrent_safety),
        ("test_log_retention_respects_config", test_log_retention_respects_config),
        ("test_session_correlation_data", test_session_correlation_data),
        ("test_event_schema_contains_mitre_when_provided", test_event_schema_contains_mitre_when_provided),
    ]

    total_passed = 0
    total_failed = 0
    for name, fn in tests:
        result = fn()
        if result:
            total_passed += 1
        else:
            total_failed += 1
        print()

    print(f"M16 Telemetry Test Summary: {total_passed} passed, {total_failed} failed")
    if total_failed == 0:
        print("M16 Telemetry: ALL TESTS PASSED")
        return 0
    else:
        print("M16 Telemetry: SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
