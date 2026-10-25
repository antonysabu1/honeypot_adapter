import asyncio

from shared.events import build_event
from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker
from shared.connection_manager import can_create_session, register_session, unregister_session
from shared.shell import LOGIN_BANNER
from telnet_adapter.session import TelnetSession


class TelnetServer(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.source_ip = transport.get_extra_info("peername")[0]
        self.buffer = ""
        self.session_id = create_session_id()
        self._rejected = False

        # ENTRY GATE: Check session limits before creating a session
        if not can_create_session("telnet", self.source_ip):
            self._rejected = True
            log_event(
                build_event(
                    session_id=self.session_id,
                    source_ip=self.source_ip,
                    protocol="telnet",
                    action="session_limit_reached",
                    parameters={"reason": "max_sessions_reached"},
                    response_status="0",
                    response_type="session_rejected",
                )
            )
            self.transport.close()
            return

        session_tracker.start_session(self.source_ip, "telnet", self.session_id)
        register_session("telnet", self.source_ip)

        log_event(
            build_event(
                session_id=self.session_id,
                source_ip=self.source_ip,
                protocol="telnet",
                action="connection_established",
                parameters={},
                response_status="0",
                response_type="banner_sent",
            )
        )

        # Ask a real Telnet client for its terminal type (RFC 1091).
        self.transport.write(b"\xff\xfd\x18")  # IAC DO TERMINAL-TYPE
        # Character mode with server-side echo, like a real telnetd; this is
        # what keeps the password from being shown as it is typed.
        self.transport.write(b"\xff\xfb\x01\xff\xfb\x03")  # WILL ECHO, WILL SGA
        self.transport.write(LOGIN_BANNER.encode())
        self.transport.write(b"login: ")
        self.session = TelnetSession(self.transport, self.session_id, self.source_ip)

    def data_received(self, data):
        # SAFETY: No subprocess/os.system — all responses via decide_response()
        self.session.handle_data(data)

    def connection_lost(self, exc):
        # A rejected connection was never registered or tracked.
        if self._rejected or self.session_id is None:
            return
        log_event(
            build_event(
                session_id=self.session_id,
                source_ip=self.source_ip,
                protocol="telnet",
                action="connection_closed",
                parameters={},
                response_status="0",
                response_type="session_end",
            )
        )
        unregister_session("telnet", self.source_ip)
        session_tracker.end_session(self.session_id)
        self.session_id = None


async def start_server(host: str = "0.0.0.0", port: int = 2323):
    loop = asyncio.get_event_loop()
    await loop.create_server(TelnetServer, host, port)
    print(f"Telnet honeypot listening on port {port}")
    await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(start_server())