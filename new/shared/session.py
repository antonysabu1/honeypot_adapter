import uuid
from datetime import datetime, timezone


def create_session_id() -> str:
    return str(uuid.uuid4())


class SessionTracker:
    def __init__(self) -> None:
        self._sessions = {}

    def start_session(self, source_ip: str, protocol: str) -> str:
        session_id = create_session_id()
        self._sessions[session_id] = {
            "source_ip": source_ip,
            "protocol": protocol,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "session_source": "protocol_native",
        }
        return session_id

    def end_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            del self._sessions[session_id]

    def get_session(self, session_id: str) -> "dict | None":
        return self._sessions.get(session_id)


tracker = SessionTracker()