import asyncio

from shared.events import build_event
from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker
from shared.shell import LOGIN_BANNER
from telnet_adapter.session import TelnetSession


class TelnetServer(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.session_id = create_session_id()
        self.source_ip = transport.get_extra_info("peername")[0]
        self.buffer = b""

        session_tracker.start_session(self.source_ip, "telnet", self.session_id)

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

        self.transport.write(LOGIN_BANNER.encode())
        self.transport.write(b"login: ")
        self.session = TelnetSession(self.transport, self.session_id, self.source_ip)

    def data_received(self, data):
        # SAFETY: No subprocess/os.system — all responses via decide_response()
        self.session.handle_data(data)

    def connection_lost(self, exc):
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
        session_tracker.end_session(self.session_id)


async def start_server():
    loop = asyncio.get_event_loop()
    server = await loop.create_server(TelnetServer, "0.0.0.0", 2323)
    print("Telnet honeypot listening on port 2323")
    await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(start_server())