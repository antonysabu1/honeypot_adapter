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

_HOST_KEY = None


def _get_host_key() -> paramiko.RSAKey:
    """Lazily load (or generate) the server host key.

    Loaded on first use rather than at import time so importing this module
    (e.g. from tests) has no filesystem side effects.
    """
    global _HOST_KEY
    if _HOST_KEY is None:
        if HOST_KEY_PATH.exists():
            _HOST_KEY = paramiko.RSAKey.from_private_key_file(str(HOST_KEY_PATH))
        else:
            _HOST_KEY = paramiko.RSAKey.generate(2048)
            _HOST_KEY.write_private_key_file(str(HOST_KEY_PATH))
    return _HOST_KEY


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
        # Lifecycle events are not attacker commands, so MITRE fields are null.
        "mitre_attack_id": None,
        "mitre_technique_name": None,
        "mitre_tactic": None,
        "mitre_attack_id_secondary": None,
        "mitre_technique_name_secondary": None,
        "mitre_confidence": None,
    }


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, session_id, client_address):
        self.session_id = session_id
        self.client_address = client_address
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
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
        self.username = username
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
        transport.add_server_key(_get_host_key())

        session_id = create_session_id()
        session_tracker.start_session(self.client_address[0], "ssh", session_id)

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

        # SAFETY: No subprocess/os.system — all responses via decide_response()
        try:
            server = HoneypotSSHServer(session_id, self.client_address)
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan is None:
                return

            server.event.wait(10)

            shell = FakeSSHShell(
                chan,
                session_id,
                self.client_address[0],
                username=server.username or "root",
            )
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
                    "response_type": "session_end",
                    "mitre_attack_id": None,
                    "mitre_technique_name": None,
                    "mitre_tactic": None,
                    "mitre_attack_id_secondary": None,
                    "mitre_technique_name_secondary": None,
                    "mitre_confidence": None,
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