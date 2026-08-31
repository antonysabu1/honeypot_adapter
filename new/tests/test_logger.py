import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.logger import LOG_FILE, REQUIRED_KEYS, log_event

SAMPLE_EVENT = {
    "event_id": str(uuid.uuid4()),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "protocol": "ssh",
    "source_ip": "192.168.1.5",
    "session_id": str(uuid.uuid4()),
    "action": "login_attempt",
    "parameters": {"username": "root", "password": "toor"},
    "raw_metadata": {"client_version": "SSH-2.0-OpenSSH_8.9", "auth_method": "password"},
    "session_source": "paramiko",
    "response_status": "accepted",
    "response_type": "fake_success",
}


def main() -> None:
    if LOG_FILE.exists():
        LOG_FILE.unlink()

    log_event(SAMPLE_EVENT)

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, f"expected 1 JSON line, got {len(lines)}"

    parsed = json.loads(lines[0])
    for key in REQUIRED_KEYS:
        assert key in parsed, f"missing key in written event: {key}"

    incomplete = {k: v for k, v in SAMPLE_EVENT.items() if k != "action"}
    try:
        log_event(incomplete)
    except ValueError as e:
        print(f"validation OK: {e}")
    else:
        raise AssertionError("log_event accepted an event with missing keys")

    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
