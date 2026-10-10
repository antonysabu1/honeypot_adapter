"""Logging-contract regression tests.

Pins the adapter contract: every event carries exactly eleven top-level fields
(event_id, timestamp, protocol, source_ip, session_id, action, parameters,
raw_metadata, session_source, response_status, response_type). MITRE ATT&CK
information is derived metadata and lives under raw_metadata["mitre"], never as a
top-level field. The transport shells log each interaction exactly once.
"""

import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import shared.logger as logger_mod
from shared.events import CONTRACT_KEYS, MITRE_KEYS, build_event, mitre_of
from shared.logger import log_event

CONTRACT = {
    "event_id", "timestamp", "protocol", "source_ip", "session_id", "action",
    "parameters", "raw_metadata", "session_source", "response_status",
    "response_type",
}

TAGS = {
    "mitre_attack_id": "T1033",
    "mitre_technique_name": "System Owner/User Discovery",
    "mitre_tactic": "Discovery",
    "mitre_attack_id_secondary": None,
    "mitre_technique_name_secondary": None,
    "mitre_confidence": "high",
}


def check(label, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}: {label}{'' if cond else ' -> ' + str(detail)}")
    return cond


def main() -> bool:
    ok = True

    ok &= check("contract has 11 keys", len(CONTRACT_KEYS) == 11, CONTRACT_KEYS)
    ok &= check("REQUIRED_KEYS is the contract", set(CONTRACT_KEYS) == CONTRACT)

    # Command event: contract keys only, MITRE nested.
    command = build_event("s-1", "1.2.3.4", "ssh", "whoami",
                          {"command": "whoami"}, "0", "command_output", mitre=dict(TAGS))
    ok &= check("command event has exactly the contract keys",
                set(command) == CONTRACT, sorted(command))
    ok &= check("command MITRE nested under raw_metadata",
                mitre_of(command).get("mitre_attack_id") == "T1033", command["raw_metadata"])
    ok &= check("command MITRE carries all six fields",
                set(command["raw_metadata"]["mitre"]) == set(MITRE_KEYS),
                command["raw_metadata"]["mitre"])

    # Login event (telnet password auth) keeps its tag nested too.
    login = build_event("s-1", "1.2.3.4", "telnet", "login_attempt",
                        {"username": "admin", "password": "x"},
                        "authenticated", "fake_auth_success", mitre=dict(TAGS))
    ok &= check("login event has exactly the contract keys", set(login) == CONTRACT)
    ok &= check("login MITRE nested", mitre_of(login).get("mitre_attack_id") == "T1033")

    # Lifecycle / disconnect event: no MITRE block at all.
    closed = build_event("s-1", "1.2.3.4", "ssh", "connection_closed", {},
                         "0", "session_end", mitre=None)
    ok &= check("disconnect event has exactly the contract keys", set(closed) == CONTRACT)
    ok &= check("disconnect event has empty raw_metadata", closed["raw_metadata"] == {})
    ok &= check("mitre_of(untagged) is empty", mitre_of(closed) == {})

    # Legacy top-level tags still summarize (backward compatibility).
    ok &= check("mitre_of falls back to legacy top-level tags",
                mitre_of({"mitre_attack_id": "T1078"}).get("mitre_attack_id") == "T1078")

    # log_event writes exactly the contract keys and rejects violations.
    tmp = Path(tempfile.mkdtemp(prefix="telemetry-contract-"))
    logger_mod.LOG_DIR = tmp
    logger_mod.LOG_FILE = tmp / "honeypot.jsonl"

    log_event(command)
    written = json.loads(logger_mod.LOG_FILE.read_text(encoding="utf-8").splitlines()[0])
    ok &= check("written event has exactly the contract keys", set(written) == CONTRACT)
    ok &= check("written event round-trips MITRE",
                mitre_of(written).get("mitre_confidence") == "high")

    import shutil
    shutil.rmtree(tmp)

    for label, bad in (
        ("missing a required key", {k: v for k, v in command.items() if k != "action"}),
        ("extra top-level key", dict(command, mitre_attack_id="T1033")),
    ):
        try:
            log_event(bad)
        except ValueError:
            ok &= check(f"log_event rejects event {label}", True)
        else:
            ok &= check(f"log_event rejects event {label}", False)

    print("\nTELEMETRY CONTRACT: " + ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
