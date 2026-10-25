import time
import uuid
from datetime import datetime, timezone

from shared.connection_manager import forget_session_commands
from shared.session_state import drop_state


def create_session_id() -> str:
    return str(uuid.uuid4())


class SessionTracker:
    def __init__(self) -> None:
        self._sessions = {}
        self._start_times: dict[str, float] = {}

    def start_session(self, source_ip: str, protocol: str, session_id: str | None = None) -> str:
        if session_id is None:
            session_id = create_session_id()
        self._sessions[session_id] = {
            "source_ip": source_ip,
            "protocol": protocol,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "session_source": "protocol_native",
        }
        self._start_times[session_id] = time.monotonic()
        try:
            from shared.storage import get_storage
            get_storage().upsert_session(session_id, source_ip, protocol)
        except Exception:
            pass
        return session_id

    def end_session(self, session_id: str) -> None:
        duration_ms: int | None = None
        if session_id in self._start_times:
            duration_ms = int((time.monotonic() - self._start_times.pop(session_id)) * 1000)
        if session_id in self._sessions:
            del self._sessions[session_id]
        try:
            from shared.storage import get_storage
            get_storage().close_session(session_id, duration_ms)
        except Exception:
            pass
        # Release attack-graph in-memory state for this session.
        try:
            from shared.attack_graph import drop_session as _drop_graph
            _drop_graph(session_id)
        except Exception:
            pass
        # The core owns per-session VirtualOS state; release it with the session.
        drop_state(session_id)
        forget_session_commands(session_id)

    def get_session(self, session_id: str) -> "dict | None":
        return self._sessions.get(session_id)


tracker = SessionTracker()