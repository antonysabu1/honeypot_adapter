#!/usr/bin/env python3
"""Summarize MITRE ATT&CK technique frequency from the honeypot JSONL log.

Reads logs/honeypot.jsonl (one JSON object per line) and prints a per-protocol
breakdown of the most-observed MITRE ATT&CK techniques, plus a quick
"distinct techniques per session" view useful for SIEM correlation.

Usage:
    python -m scripts.technique_summary                 # default log path
    python -m scripts.technique_summary path/to/log.jsonl
    python -m scripts.technique_summary --top 5
    python -m scripts.technique_summary --per-session
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = PROJECT_ROOT / "logs" / "honeypot.jsonl"

TECH_NAMES = {
    "T1005": "Data from Local System",
    "T1007": "System Service Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1049": "System Network Connections Discovery",
    "T1053": "Scheduled Task/Job",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1222": "File and Directory Permissions Modification",
    "T1485": "Data Destruction",
    "T1489": "Service Stop",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1555": "Credentials from Password Stores",
    "T1560": "Archive Collected Data",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal on Host",
    "T0842": "Network Sniffing",
    "T0809": "Data Destruction (ICS)",
    "T0855": "Unauthorized Command Message (ICS)",
    "T0859": "Valid Accounts (ICS)",
    "T0861": "Connection Proxy (ICS)",
    "T0869": "Standard Application Layer Protocol (ICS)",
    "T0888": "System Firmware (ICS)",
}


def _name(tech_id: str) -> str:
    return TECH_NAMES.get(tech_id, tech_id)


def _events(lines):
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def summarize(log_path, top, per_session):
    with open(log_path, encoding="utf-8") as f:
        events = list(_events(f))

    by_proto = defaultdict(Counter)
    total = 0
    for e in events:
        tid = e.get("mitre_attack_id")
        if not tid:
            continue
        proto = e.get("protocol", "?")
        by_proto[proto][tid] += 1
        total += 1

    print(f"Log: {log_path}")
    print(f"Technique-tagged events: {total}\n")

    if per_session:
        _print_per_session(events)

    for proto, counter in sorted(by_proto.items()):
        print(f"=== {proto.upper()} ===")
        for tid, count in counter.most_common(top):
            print(f"  {tid:8} {count:5}  {_name(tid)}")
        print()


def _print_per_session(events):
    session_techs = defaultdict(set)
    for e in events:
        tid = e.get("mitre_attack_id")
        sid = e.get("session_id")
        if tid and sid:
            session_techs[sid].add(tid)

    multi = {sid: t for sid, t in session_techs.items() if len(t) >= 3}
    print(f"=== SESSIONS WITH >=3 DISTINCT TECHNIQUES ({len(multi)}) ===")
    for sid, techs in sorted(
        multi.items(), key=lambda kv: len(kv[1]), reverse=True
    ):
        print(f"  {sid}  ({len(techs)}): {', '.join(sorted(techs))}")
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("log", nargs="?", default=str(DEFAULT_LOG),
                        help="path to honeypot.jsonl (default: logs/honeypot.jsonl)")
    parser.add_argument("--top", type=int, default=10,
                        help="number of techniques to show per protocol")
    parser.add_argument("--per-session", action="store_true",
                        help="also show sessions with many distinct techniques")
    args = parser.parse_args()

    if not Path(args.log).exists():
        print(f"Log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    summarize(args.log, args.top, args.per_session)


if __name__ == "__main__":
    main()
