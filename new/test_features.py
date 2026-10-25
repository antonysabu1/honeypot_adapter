"""Unit tests for shared/features.py feature extraction."""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import shared.storage as storage_mod
from shared.storage import StorageEngine
from shared.features import extract_session_features, FEATURE_NAMES


def _setup() -> tuple[StorageEngine, str]:
    tmp = Path(tempfile.mkdtemp(prefix="honeypot-features-test-"))
    se = StorageEngine(tmp / "test.db")
    return se, str(tmp / "test.db")


def test_feature_count():
    se, db_path = _setup()
    se.upsert_session("s1", "1.2.3.4", "ssh")
    se.insert_event(session_id="s1", protocol="ssh", action="whoami",
                    parameters={"command": "whoami", "name": "whoami", "args": []},
                    response_type="command_output", status="0")
    se._close()
    feats = extract_session_features("s1", db_path=db_path)
    assert len(feats) == len(FEATURE_NAMES), f"expected {len(FEATURE_NAMES)}, got {len(feats)}"
    print("PASS test_feature_count")


def test_recon_flag():
    se, db_path = _setup()
    se.upsert_session("s2", "1.2.3.4", "ssh")
    for cmd in ("whoami", "id", "uname"):
        se.insert_event(session_id="s2", protocol="ssh", action=cmd,
                        parameters={"command": cmd, "name": cmd, "args": []},
                        response_type="command_output", status="0")
    se._close()
    feats = extract_session_features("s2", db_path=db_path)
    idx = FEATURE_NAMES.index("has_recon")
    assert feats[idx] == 1.0, f"has_recon should be 1.0, got {feats[idx]}"
    print("PASS test_recon_flag")


def test_lure_access_flag():
    se, db_path = _setup()
    se.upsert_session("s3", "1.2.3.4", "ssh")
    se.insert_event(session_id="s3", protocol="ssh",
                    action="cat /root/.aws/credentials",
                    parameters={"command": "cat /root/.aws/credentials",
                                "name": "cat", "args": ["/root/.aws/credentials"]},
                    response_type="command_output", status="0")
    se._close()
    feats = extract_session_features("s3", db_path=db_path)
    idx = FEATURE_NAMES.index("has_lure_access")
    assert feats[idx] == 1.0, f"has_lure_access should be 1.0, got {feats[idx]}"
    print("PASS test_lure_access_flag")


def test_missing_session_raises():
    se, db_path = _setup()
    se._close()
    try:
        extract_session_features("nonexistent", db_path=db_path)
        assert False, "should have raised ValueError"
    except ValueError:
        pass
    print("PASS test_missing_session_raises")


def test_no_recon_no_flag():
    se, db_path = _setup()
    se.upsert_session("s4", "1.2.3.4", "ssh")
    se.insert_event(session_id="s4", protocol="ssh", action="ls /tmp",
                    parameters={"command": "ls /tmp", "name": "ls", "args": ["/tmp"]},
                    response_type="command_output", status="0")
    se._close()
    feats = extract_session_features("s4", db_path=db_path)
    idx = FEATURE_NAMES.index("has_recon")
    assert feats[idx] == 0.0, f"has_recon should be 0.0, got {feats[idx]}"
    print("PASS test_no_recon_no_flag")


def main():
    test_feature_count()
    test_recon_flag()
    test_lure_access_flag()
    test_missing_session_raises()
    test_no_recon_no_flag()
    print("\nALL FEATURE TESTS PASSED")


if __name__ == "__main__":
    main()
