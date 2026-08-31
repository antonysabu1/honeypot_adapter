import socketserver
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

# paramiko is a required third-party dependency. It is installed (v5.0.0).
import paramiko

from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker
from ssh_adapter.shell import FakeSSHShell

HOST_KEY_PATH = Path(__file__).resolve().parent / "host_key"


def _load_or_create_host_key() -> paramiko.RSAKey:
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey.from_private_key_file(str(HOST_KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    return key


HOST_KEY = _load_or_create_host_key()


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


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, session_id, client_address):
        self.session_id = session_id
        self.client_address = client_address
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_event(
            _build_event(
                session_id=self.session_id,
                source_ip=self.client_address[0],
                protocol="ssh",
                action="login_attempt",
                parameters={"username": username, "password": password},
                response_status="authenticated",
                response_type="fake_auth_success",
            )
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        log_event(
            _build_event(
                session_id=self.session_id,
                source_ip=self.client_address[0],
                protocol="ssh",
                action="pubkey_attempt",
                parameters={
                    "username": username,
                    "fingerprint": key.get_fingerprint().hex(),
                },
                response_status="authenticated",
                response_type="fake_auth_success",
            )
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        transport = paramiko.Transport(self.request)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        transport.add_server_key(HOST_KEY)

        session_id = create_session_id()
        session_tracker.start_session(self.client_address[0], "ssh")

        log_event(
            _build_event(
                session_id=session_id,
                source_ip=self.client_address[0],
                protocol="ssh",
                action="connection_established",
                parameters={},
                response_status="0",
                response_type="banner_sent",
            )
        )

        server = HoneypotSSHServer(session_id, self.client_address)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            return

        server.event.wait(10)
        if chan is None:
            return

        shell = FakeSSHShell(chan, session_id, self.client_address[0])
        # SAFETY: No subprocess/os.system — all responses via decide_response()
        try:
            shell.run()
        finally:
            log_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "protocol": "ssh",
                    "source_ip": self.client_address[0],
                    "session_id": session_id,
                    "action": "connection_closed",
                    "parameters": {},
                    "raw_metadata": {},
                    "session_source": "protocol_native",
                    "response_status": "0",
                    "response_type": "session_ended",
                }
            )
            session_tracker.end_session(session_id)
            transport.close()


def start_server():
    server = socketserver.ThreadingTCPServer(("", 2222), SSHHandler)
    server.allow_reuse_address = True
    server.daemon_threads = True
    print("SSH honeypot listening on port 2222")
    server.serve_forever()


if __name__ == "__main__":
    start_server()