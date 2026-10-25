import socketserver
import threading
import time
from pathlib import Path

# paramiko is a required third-party dependency. It is installed (v5.0.0).
import paramiko

from shared.events import build_event as _build_event
from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker
from shared.connection_manager import can_create_session, register_session, unregister_session
from ssh_adapter.shell import FakeSSHShell

HOST_KEY_PATH = Path(__file__).resolve().parent / "host_key"

# Channels one connection may have open at once (OpenSSH's default is 10).
MAX_CHANNELS = 10
# A connection with no open channel is dropped after this many seconds.
IDLE_SECONDS = 30

_HOST_KEY = None


def _text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


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


class ChannelInfo:
    """What one session channel has asked for so far (pty, shell or exec)."""

    def __init__(self) -> None:
        self.term = None
        self.exec_command = None
        # Set once the client sends its shell or exec request.
        self.ready = threading.Event()


class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, session_id, client_address, transport=None):
        self.session_id = session_id
        self.client_address = client_address
        self.transport = transport
        self.username = None
        self.channels: dict[int, ChannelInfo] = {}
        self.open_channels = 0
        self._lock = threading.Lock()

    def channel_info(self, channel) -> ChannelInfo:
        with self._lock:
            return self.channels.setdefault(channel.chanid, ChannelInfo())

    def _client_metadata(self, channel=None) -> dict:
        """Protocol fingerprint data for the client's events."""
        metadata = {}
        version = _text(getattr(getattr(self, "transport", None), "remote_version", None))
        if version:
            metadata["client_version"] = version
        term = _text(self.channel_info(channel).term) if channel is not None else None
        if term:
            metadata["terminal_type"] = term
        return metadata

    def check_channel_request(self, kind, chanid):
        if kind != "session":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        if self.open_channels >= MAX_CHANNELS:
            return paramiko.OPEN_FAILED_RESOURCE_SHORTAGE
        return paramiko.OPEN_SUCCEEDED

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
                raw_metadata=self._client_metadata(),
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
                raw_metadata=self._client_metadata(),
            )
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.channel_info(channel).ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # `ssh host "cmd"`: accepted like sshd would, answered by the fake shell.
        info = self.channel_info(channel)
        info.exec_command = _text(command)
        info.ready.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        self.channel_info(channel).term = term
        return True


class SSHHandler(socketserver.BaseRequestHandler):
    def _serve_channel(self, server, chan, session_id):
        """Run one channel's shell or exec; channels share the session."""
        try:
            info = server.channel_info(chan)
            info.ready.wait(10)
            shell = FakeSSHShell(
                chan,
                session_id,
                self.client_address[0],
                username=server.username or "root",
                raw_metadata=server._client_metadata(chan),
            )
            if info.exec_command is not None:
                shell.run_exec(info.exec_command)
            else:
                shell.run()
        finally:
            with server._lock:
                server.open_channels -= 1
            server.channels.pop(chan.chanid, None)
            try:
                chan.close()
            except Exception:
                pass

    def handle(self):
        transport = paramiko.Transport(self.request)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        transport.add_server_key(_get_host_key())

        source_ip = self.client_address[0]
        session_id = create_session_id()

        # ENTRY GATE: Check session limits before creating a session
        if not can_create_session("ssh", source_ip):
            log_event(
                _build_event(
                    session_id=session_id,
                    source_ip=source_ip,
                    protocol="ssh",
                    action="session_limit_reached",
                    parameters={"reason": "max_sessions_reached"},
                    response_status="0",
                    response_type="session_rejected",
                )
            )
            transport.close()
            return

        session_tracker.start_session(source_ip, "ssh", session_id)
        register_session("ssh", source_ip)

        log_event(
            _build_event(
                session_id=session_id,
                source_ip=source_ip,
                protocol="ssh",
                action="connection_established",
                parameters={},
                response_status="0",
                response_type="banner_sent",
            )
        )

        # SAFETY: No subprocess/os.system — all responses via decide_response()
        try:
            server = HoneypotSSHServer(session_id, self.client_address, transport)
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan is None:
                return

            workers = []
            idle_since = time.monotonic()
            while chan is not None or transport.is_active():
                if chan is not None:
                    worker = threading.Thread(
                        target=self._serve_channel,
                        args=(server, chan, session_id),
                        daemon=True,
                    )
                    with server._lock:
                        server.open_channels += 1
                    worker.start()
                    workers.append(worker)
                chan = transport.accept(1)
                workers = [w for w in workers if w.is_alive()]
                if workers or chan is not None:
                    idle_since = time.monotonic()
                elif time.monotonic() - idle_since > IDLE_SECONDS:
                    break
            for worker in workers:
                worker.join(timeout=5)
        finally:
            log_event(
                _build_event(
                    session_id=session_id,
                    source_ip=source_ip,
                    protocol="ssh",
                    action="connection_closed",
                    parameters={},
                    response_status="0",
                    response_type="session_end",
                    raw_metadata={
                        "client_version": _text(
                            getattr(transport, "remote_version", None)
                        )
                    } if getattr(transport, "remote_version", None) else None,
                )
            )
            unregister_session("ssh", source_ip)
            session_tracker.end_session(session_id)
            # Let the client read the channel close and hang up first, so the
            # session ends with a clean disconnect, not a reset connection.
            transport.join(timeout=2)
            transport.close()


def start_server(port: int = 2222):
    server = socketserver.ThreadingTCPServer(("", port), SSHHandler)
    server.allow_reuse_address = True
    server.daemon_threads = True
    print(f"SSH honeypot listening on port {port}")
    server.serve_forever()


if __name__ == "__main__":
    start_server()