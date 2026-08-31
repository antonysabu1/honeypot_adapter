import asyncio
from datetime import datetime, timezone
import uuid

from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker


def _build_event(
    session_id,
    source_ip,
    protocol,
    action,
    parameters,
    response_status,
    response_type,
) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": protocol,
        "source_ip": source_ip,
        "session_id": session_id,
        "action": action,
        "parameters": parameters,
        "raw_metadata": {},
        "session_source": "protocol_native",
        "response_status": response_status,
        "response_type": response_type,
    }


class TelnetServer(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.session_id = create_session_id()
        self.source_ip = transport.get_extra_info("peername")[0]
        self.buffer = b""

        session_tracker.start_session(self.source_ip, "telnet")

        log_event(
            _build_event(
                session_id=self.session_id,
                source_ip=self.source_ip,
                protocol="telnet",
                action="connection_established",
                parameters={},
                response_status="0",
                response_type="banner_sent",
            )
        )

        self.transport.write(b"\r\nWelcome to Ubuntu 22.04 LTS\r\n\r\n")

    def data_received(self, data):
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 255:  # IAC — skip 3-byte sequence
                i += 3
                continue
            if byte in (13, 10):  # \r or \n
                if self.buffer:
                    self.handle_data(self.buffer.decode("utf-8", errors="ignore"))
                    self.buffer = b""
                i += 1
                continue
            self.buffer += bytes([byte])
            i += 1

    def handle_data(self, line):
        # Part 9 will implement login/shell
        pass

    def connection_lost(self, exc):
        log_event(
            _build_event(
                session_id=self.session_id,
                source_ip=self.source_ip,
                protocol="telnet",
                action="connection_closed",
                parameters={},
                response_status="0",
                response_type="session_ended",
            )
        )
        session_tracker.end_session(self.session_id)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = loop.create_server(TelnetServer, "0.0.0.0", 2323)
    server = loop.run_until_complete(coro)
    print("Telnet honeypot listening on port 2323")
    loop.run_forever()