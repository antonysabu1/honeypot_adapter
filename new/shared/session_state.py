"""Per-session VirtualOS state, owned by the core and keyed by session_id.

Transports never hold a filesystem or shell state of their own: they hand
``decide_response()`` a session_id and the engine looks the state up here.
That keeps the decision seam at (session_id, action, parameters), so the
engine behind it can be replaced without touching any transport.

State is created on a session's first command and dropped when the session
ends (``shared.session.SessionTracker.end_session``).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from shared.filesystem import FakeFilesystem
from shared.shell_state import VirtualShellState


@dataclass
class SessionState:
    fs: FakeFilesystem
    shell: VirtualShellState


_STATES: dict[str, SessionState] = {}
# Paramiko serves each connection on its own thread.
_LOCK = threading.Lock()


def _new_state(username: str) -> SessionState:
    # The honeypot always presents a root shell; only whoami reflects the
    # actual login user (per session-isolation report recommendation).
    return SessionState(
        fs=FakeFilesystem(),
        shell=VirtualShellState(
            user=username,
            uid=0,
            gid=0,
            groups=frozenset([0]),
            cwd="/root",
            old_pwd="/",
            home="/root",
            shell="/bin/bash",
            term="xterm-256color",
        ),
    )


def get_state(session_id: str, username: str = "root") -> SessionState:
    """Return the session's state, creating it on first use."""
    with _LOCK:
        state = _STATES.get(session_id)
        if state is None:
            state = _STATES[session_id] = _new_state(username)
        return state


def drop_state(session_id: str) -> None:
    """Forget a finished session's state."""
    with _LOCK:
        _STATES.pop(session_id, None)
