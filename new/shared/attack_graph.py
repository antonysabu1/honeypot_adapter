"""Attack progression graph for SSH/Telnet honeypot sessions.

Tracks how far an attacker has progressed through a standard SSH
intrusion kill chain.  Each session starts with all nodes locked;
nodes unlock as the attacker takes the matching actions.

The graph has 10 nodes in a rough linear chain:
  authenticated → ran_recon → ran_discovery → found_lure_file
  → read_credentials → attempted_persistence → ran_exfil
  → modified_crontab → added_user → destructive_action

Node unlocking is stored in the SQLite sessions table via a side table
(session_attack_nodes) so it survives across reporting queries.

The graph is checked after every log_event() call (best-effort, never
raises) and logs a special node_unlocked event when a new node is first
reached.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Node definitions
# ---------------------------------------------------------------------------

NODES: dict[str, dict] = {
    "authenticated": {
        "description": "Attacker authenticated successfully",
        "trigger": "connection_established",
        "mitre": "T1078",
    },
    "ran_recon": {
        "description": "Attacker ran a recon command (whoami, id, uname…)",
        "trigger": "recon_command",
        "mitre": "T1033",
    },
    "ran_discovery": {
        "description": "Attacker ran a discovery command (find, ls /etc, ps…)",
        "trigger": "discovery_command",
        "mitre": "T1083",
    },
    "found_lure_file": {
        "description": "Attacker accessed one of the planted lure files",
        "trigger": "lure_file_read",
        "mitre": "T1552",
    },
    "read_credentials": {
        "description": "Attacker read a credential file (/etc/shadow, .aws, .ssh…)",
        "trigger": "credential_read",
        "mitre": "T1552",
    },
    "attempted_persistence": {
        "description": "Attacker ran a persistence command (crontab, useradd…)",
        "trigger": "persistence_command",
        "mitre": "T1053",
    },
    "ran_exfil": {
        "description": "Attacker ran a data-exfiltration tool (curl, wget, nc…)",
        "trigger": "exfil_command",
        "mitre": "T1048",
    },
    "modified_crontab": {
        "description": "Attacker used crontab -e or wrote to cron directory",
        "trigger": "crontab_write",
        "mitre": "T1053",
    },
    "added_user": {
        "description": "Attacker added or modified a system user",
        "trigger": "user_add",
        "mitre": "T1098",
    },
    "destructive_action": {
        "description": "Attacker ran a destructive command (rm -rf, shred…)",
        "trigger": "destructive_command",
        "mitre": "T1485",
    },
}

_RECON_CMDS = frozenset(["whoami", "id", "uname", "hostname", "w", "who", "last", "uptime"])
_DISCOVERY_CMDS = frozenset(["find", "locate", "ls", "cat", "less", "more", "grep",
                              "ps", "netstat", "ss", "df", "du", "env", "printenv"])
_PERSIST_CMDS   = frozenset(["crontab", "useradd", "adduser", "chpasswd", "visudo",
                              "systemctl", "service"])
_EXFIL_CMDS     = frozenset(["curl", "wget", "scp", "sftp", "rsync", "nc", "ncat",
                              "python", "python3", "perl"])
_DESTROY_CMDS   = frozenset(["rm", "shred", "dd", "mkfs", "truncate"])
_LURE_PATHS = ("/root/.aws/credentials", "/root/.ssh/id_rsa",
               "/var/www/html/config.php", "/etc/mysql/my.cnf",
               "/root/.bash_history")
_CRED_PATHS = ("/etc/shadow", ".ssh/id_rsa", ".ssh/id_dsa", ".aws/credentials",
               "config.php", "my.cnf", ".bash_history", ".netrc")


def _classify_event(action: str, params: dict) -> set[str]:
    """Return the set of trigger names fired by this event."""
    triggers: set[str] = set()
    name = params.get("name", action.split()[0] if action else "")
    args = params.get("args", [])
    arg_str = " ".join(str(a) for a in args)
    full = action + " " + arg_str

    if action in ("connection_established", "login_attempt"):
        triggers.add("connection_established")
    if name in _RECON_CMDS:
        triggers.add("recon_command")
    if name in _DISCOVERY_CMDS:
        triggers.add("discovery_command")
    if name in _PERSIST_CMDS:
        triggers.add("persistence_command")
        if name == "crontab":
            triggers.add("crontab_write")
        if name in ("useradd", "adduser", "chpasswd"):
            triggers.add("user_add")
    if name in _EXFIL_CMDS:
        triggers.add("exfil_command")
    if name in _DESTROY_CMDS:
        triggers.add("destructive_command")
    if any(p in full for p in _LURE_PATHS):
        triggers.add("lure_file_read")
    if any(p in full for p in _CRED_PATHS):
        triggers.add("credential_read")
    return triggers


# ---------------------------------------------------------------------------
# Per-session node tracking (in-memory; also persisted to SQLite)
# ---------------------------------------------------------------------------

import threading

_SESSION_NODES: dict[str, set[str]] = {}
_LOCK = threading.Lock()

_SCHEMA_MIGRATION = """
CREATE TABLE IF NOT EXISTS session_attack_nodes (
    session_id TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    unlocked_at TEXT NOT NULL,
    PRIMARY KEY (session_id, node_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
"""


def _ensure_table(conn) -> None:
    conn.executescript(_SCHEMA_MIGRATION)
    conn.commit()


def get_unlocked_nodes(session_id: str) -> set[str]:
    """Return the set of node IDs already unlocked for *session_id*."""
    with _LOCK:
        return set(_SESSION_NODES.get(session_id, set()))


def evaluate_event(session_id: str, action: str, params: dict) -> list[str]:
    """Update the graph for one event; return list of newly unlocked node IDs.

    Persists newly unlocked nodes to SQLite (best-effort).
    """
    triggers = _classify_event(action, params)
    if not triggers:
        return []

    newly_unlocked: list[str] = []
    with _LOCK:
        current = _SESSION_NODES.setdefault(session_id, set())
        for node_id, node in NODES.items():
            if node_id not in current and node["trigger"] in triggers:
                current.add(node_id)
                newly_unlocked.append(node_id)

    if newly_unlocked:
        _persist_nodes(session_id, newly_unlocked)
    return newly_unlocked


def _persist_nodes(session_id: str, node_ids: list[str]) -> None:
    try:
        from shared.storage import get_storage
        store = get_storage()
        _ensure_table(store._conn)
        now = datetime.now(timezone.utc).isoformat()
        for node_id in node_ids:
            store._conn.execute(
                "INSERT OR IGNORE INTO session_attack_nodes (session_id, node_id, unlocked_at) VALUES (?, ?, ?)",
                (session_id, node_id, now),
            )
        store._conn.commit()
    except Exception:
        pass


def drop_session(session_id: str) -> None:
    """Release in-memory graph state for a finished session."""
    with _LOCK:
        _SESSION_NODES.pop(session_id, None)


def session_progress(session_id: str) -> dict:
    """Return a summary of the session's attack progression."""
    unlocked = get_unlocked_nodes(session_id)
    nodes_summary = []
    for node_id, node in NODES.items():
        nodes_summary.append({
            "id": node_id,
            "description": node["description"],
            "mitre": node["mitre"],
            "unlocked": node_id in unlocked,
        })
    return {
        "session_id": session_id,
        "nodes_unlocked": len(unlocked),
        "nodes_total": len(NODES),
        "nodes": nodes_summary,
    }
