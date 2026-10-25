"""Session feature extraction for attack-stage classification.

Computes a fixed-order numeric feature vector from a session's SQLite
records.  Both training-data generation and live inference import
FEATURE_NAMES and extract_session_features() from here so the feature
order is always identical.

Feature set mirrors the HTTP honeypot's features.py, adapted for
SSH/Telnet command semantics instead of HTTP request patterns.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

FEATURE_NAMES = [
    "command_count",          # total commands run in session
    "command_rate",           # commands per minute
    "distinct_commands",      # number of unique command names
    "error_ratio",            # commands that returned non-zero exit / error response
    "has_recon",              # whoami, id, uname, hostname, ifconfig, ip addr
    "has_discovery",          # find, locate, ls /etc, cat /etc/passwd, ps, netstat
    "has_credential_access",  # cat ~/.ssh, cat /etc/shadow, cat /.aws, cat config.php
    "has_persistence",        # crontab, useradd, echo >> /etc/rc, systemctl enable
    "has_exfil",              # curl, wget, scp, nc, python -c socket
    "has_lure_access",        # attacker read one of the seeded lure files
    "session_duration_s",     # seconds since session started
]

# Commands that map to each feature flag
_RECON_CMDS = frozenset(["whoami", "id", "uname", "hostname", "ifconfig", "ip",
                          "w", "who", "last", "uptime", "dmesg"])
_DISCOVERY_CMDS = frozenset(["find", "locate", "ls", "cat", "less", "more",
                              "head", "tail", "grep", "ps", "netstat", "ss",
                              "lsof", "df", "du", "mount", "env", "printenv"])
_CRED_PATHS = ("/etc/shadow", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa",
               ".aws/credentials", "config.php", "my.cnf", ".bash_history",
               ".netrc", "wp-config.php", ".pgpass")
_PERSISTENCE_CMDS = frozenset(["crontab", "useradd", "adduser", "chpasswd",
                                "visudo", "systemctl", "service", "rc-update"])
_EXFIL_CMDS = frozenset(["curl", "wget", "scp", "sftp", "rsync", "nc",
                          "ncat", "python", "python3", "perl", "ruby",
                          "base64", "xxd", "socat"])
_LURE_PATHS = ("/root/.aws/credentials", "/root/.ssh/id_rsa",
               "/var/www/html/config.php", "/etc/mysql/my.cnf",
               "/root/.bash_history")


def _is_credential_action(action: str, params: dict) -> bool:
    args = params.get("args", [])
    cmd_line = action + " " + " ".join(str(a) for a in args)
    return any(p in cmd_line for p in _CRED_PATHS)


def _is_lure_access(action: str, params: dict) -> bool:
    args = params.get("args", [])
    cmd_line = action + " " + " ".join(str(a) for a in args)
    return any(p in cmd_line for p in _LURE_PATHS)


def extract_session_features(session_id: str, db_path: str | None = None) -> list[float]:
    """Return a fixed-order numeric feature vector for *session_id*.

    Reads from the SQLite store.  Raises ValueError when the session is
    not found.
    """
    from shared.storage import get_storage, StorageEngine
    from pathlib import Path

    if db_path is not None:
        store: StorageEngine = StorageEngine(db_path)
    else:
        store = get_storage()

    sess = store.fetch_one(
        "SELECT started_at, last_seen, request_count FROM sessions WHERE session_id=?",
        (session_id,),
    )
    if sess is None:
        raise ValueError(f"Session {session_id!r} not found in sessions table")

    logs = store.fetch_all(
        "SELECT action, parameters, response_type, status FROM events "
        "WHERE session_id=? ORDER BY timestamp ASC",
        (session_id,),
    )

    command_count = len(logs)

    try:
        started = datetime.fromisoformat(sess["started_at"])
        last = datetime.fromisoformat(sess["last_seen"] or sess["started_at"])
        duration_s = max(0.0, (last - started).total_seconds())
    except (TypeError, ValueError):
        duration_s = 0.0

    duration_min = duration_s / 60.0
    command_rate = command_count / duration_min if duration_min > 0 else float(command_count)

    distinct_commands = len({
        (json.loads(p).get("name") if isinstance(p, str) else (p or {}).get("name"))
        for _, p, _, _ in (
            (r["action"], r["parameters"], r["response_type"], r["status"])
            for r in logs
        )
        if p
    })

    error_count = 0
    has_recon = False
    has_discovery = False
    has_cred = False
    has_persist = False
    has_exfil = False
    has_lure = False

    for row in logs:
        rtype = row["response_type"] or ""
        status = str(row["status"] or "0")
        if rtype in ("command_not_found", "cd_failed") or status not in ("0", ""):
            error_count += 1

        try:
            params = json.loads(row["parameters"]) if isinstance(row["parameters"], str) else (row["parameters"] or {})
        except (json.JSONDecodeError, TypeError):
            params = {}

        name = params.get("name", row["action"].split()[0] if row["action"] else "")

        if name in _RECON_CMDS:
            has_recon = True
        if name in _DISCOVERY_CMDS:
            has_discovery = True
        if name in _PERSISTENCE_CMDS:
            has_persist = True
        if name in _EXFIL_CMDS:
            has_exfil = True
        if _is_credential_action(row["action"], params):
            has_cred = True
        if _is_lure_access(row["action"], params):
            has_lure = True

    error_ratio = error_count / command_count if command_count > 0 else 0.0

    now = datetime.now(timezone.utc)
    try:
        session_duration_s = (now - started).total_seconds()
    except Exception:
        session_duration_s = 0.0

    if db_path is not None:
        store._close()

    return [
        float(command_count),
        command_rate,
        float(distinct_commands),
        error_ratio,
        1.0 if has_recon else 0.0,
        1.0 if has_discovery else 0.0,
        1.0 if has_cred else 0.0,
        1.0 if has_persist else 0.0,
        1.0 if has_exfil else 0.0,
        1.0 if has_lure else 0.0,
        session_duration_s,
    ]
