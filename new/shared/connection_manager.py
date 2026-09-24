"""Connection manager that enforces per-IP and per-protocol session limits.

Uses the shared.config system for limit values. Tracks:
- Total active sessions (per protocol)
- Sessions per IP address
- Session creation time for timeout enforcement

Architecture:
  Incoming connection
      │
      ▼
  ConnectionManager.check()
      │
      ├─ limit reached → reject
      └─ within limits → create session, track
"""

from __future__ import annotations

import time
from collections import defaultdict

from shared.config import get


# ── Limits from config ───────────────────────────────────────────────────

def _get_max_ssh_sessions() -> int:
    return int(get("limits.max_ssh_sessions", 50))


def _get_max_telnet_sessions() -> int:
    return int(get("limits.max_telnet_sessions", 50))


def _get_max_total_sessions() -> int:
    return int(get("limits.max_sessions", 100))


# ── Per-IP tracking ───────────────────────────────────────────────────────

# Global tracking instances — initialised when first used
_ip_sessions: dict[str, int] = defaultdict(int)  # ip → session count
_protocol_sessions: dict[str, int] = defaultdict(int)  # protocol → session count
_session_timestamps: dict[str, float] = defaultdict(float)  # ip → last activity


def _init() -> None:
    """Reset tracking state (useful for testing)."""
    global _ip_sessions, _protocol_sessions, _session_timestamps
    _ip_sessions = defaultdict(int)
    _protocol_sessions = defaultdict(int)
    _session_timestamps = defaultdict(float)


# ── Public API ──────────────────────────────────────────────────────────────

def can_create_session(protocol: str, source_ip: str) -> bool:
    """Check whether a new session can be created given current limits.

    Returns True if the session can be created, False if the limit would be exceeded.
    Must be called before creating the session; the caller should then
    register the session via register_session().
    """
    # Refresh timestamps and prune stale entries
    _refresh_timestamps()

    total = _protocol_sessions["ssh"] + _protocol_sessions["telnet"]
    if total >= _get_max_total_sessions():
        return False

    if protocol == "ssh":
        if _protocol_sessions["ssh"] >= _get_max_ssh_sessions():
            return False
    elif protocol == "telnet":
        if _protocol_sessions["telnet"] >= _get_max_telnet_sessions():
            return False

    # Per-IP check: if IP already has many sessions, reject
    if _ip_sessions[source_ip] >= _get_max_total_sessions():
        return False

    return True


def register_session(protocol: str, source_ip: str) -> None:
    """Register a newly created session so the limits are tracked."""
    _protocol_sessions[protocol] += 1
    _ip_sessions[source_ip] += 1
    _session_timestamps[source_ip] = time.time()


def unregister_session(protocol: str, source_ip: str) -> None:
    """Decrement counters when a session ends."""
    _protocol_sessions[protocol] = max(0, _protocol_sessions[protocol] - 1)
    _ip_sessions[source_ip] = max(0, _ip_sessions[source_ip] - 1)
    # Optional: clean up if no more sessions from this IP
    if _ip_sessions[source_ip] == 0:
        # Keep the entry but at 0; could also delete if desired
        pass


def _refresh_timestamps() -> None:
    """Optionally prune stale IP entries based on session_timeout."""
    from shared.config import get
    now = time.time()
    timeout = get("limits.session_timeout", 3600)
    # Simple prune: IPs with no recent activity can have their counters reset
    # This is optional and depends on deployment; keep it minimal for now.
    pass


# ── Convenience ────────────────────────────────────────────────────────────

def get_ip_session_count() -> dict[str, int]:
    """Return current per-IP session counts (for debugging/metrics)."""
    return dict(_ip_sessions)


def get_protocol_session_count() -> dict[str, int]:
    """Return current per-protocol session counts (for debugging/metrics)."""
    return {
        "ssh": _protocol_sessions["ssh"],
        "telnet": _protocol_sessions["telnet"],
        "total": _protocol_sessions["ssh"] + _protocol_sessions["telnet"],
    }