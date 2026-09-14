"""AsyncSSH-based SSH server (experimental transport).

Replaces the Paramiko transport (ssh_adapter/server.py) while producing the
same telemetry events and leaving the honeypot core untouched.

    SSH  ->  AsyncSSH  ->  AsyncSSHShell  ->  Response Engine

Select with:  HONEYPOT_SSH_ADAPTER=asyncssh python main.py
"""

import asyncio
from pathlib import Path

import asyncssh

from asyncssh_adapter.events import build_event
from asyncssh_adapter.shell import AsyncSSHShell
from shared.logger import log_event
from shared.session import create_session_id, tracker as session_tracker

HOST_KEY_FILE = Path(__file__).resolve().parent / "host_key_asyncssh"

SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"


def _load_host_key():
    """Load a persisted host key or generate one (mirrors Paramiko path)."""
    if HOST_KEY_FILE.exists():
        try:
            return asyncssh.import_private_key(HOST_KEY_FILE.read_bytes())
        except Exception:
            pass
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
    except Exception:
        key = asyncssh.generate_private_key("ssh-rsa", 2048)
    try:
        HOST_KEY_FILE.write_bytes(key.export_private_key())
    except Exception:
        pass
    return key


class HoneypotSSHServer(asyncssh.SSHServer):
    """AsyncSSH server: permissive auth + fake shell mirroring Paramiko."""

    def __init__(self):
        self._conn = None
        self._ip = "0.0.0.0"
        self._session_id = None
        self._username = None

    # ------------------------------------------------------------------
    # Connection lifecycle / telemetry
    # ------------------------------------------------------------------
    def connection_made(self, conn) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        self._ip = peer[0]
        self._session_id = create_session_id()
        session_tracker.start_session(self._ip, "ssh", self._session_id)

        log_event(build_event(
            session_id=self._session_id,
            source_ip=self._ip,
            protocol="ssh",
            action="connection_established",
            parameters={},
            response_status="0",
            response_type="banner_sent",
        ))

    def connection_lost(self, exc) -> None:
        if self._session_id is None:
            return
        log_event(build_event(
            session_id=self._session_id,
            source_ip=self._ip,
            protocol="ssh",
            action="connection_closed",
            parameters={},
            response_status="0",
            response_type="session_end",
        ))
        session_tracker.end_session(self._session_id)

    # ------------------------------------------------------------------
    # Authentication (permissive — mirrors Paramiko adapter behavior)
    # ------------------------------------------------------------------
    def begin_auth(self, username: str) -> bool:
        """Return True so authentication proceeds for every user.

        AsyncSSH's contract here is a bool: `True` means "credentials are
        required, continue", `False` means "no authentication needed, let the
        client straight in". The methods actually offered are declared by
        password_auth_supported() / public_key_auth_supported() below.
        """
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self._username = username
        log_event(build_event(
            session_id=self._session_id,
            source_ip=self._ip,
            protocol="ssh",
            action="login_attempt",
            parameters={"username": username, "password": password},
            response_status="authenticated",
            response_type="fake_auth_success",
        ))
        return True

    def validate_public_key(self, username: str, key) -> bool:
        self._username = username
        try:
            fingerprint = key.get_fingerprint()
        except Exception:
            fingerprint = str(key)
        log_event(build_event(
            session_id=self._session_id,
            source_ip=self._ip,
            protocol="ssh",
            action="pubkey_attempt",
            parameters={"username": username, "fingerprint": fingerprint},
            response_status="authenticated",
            response_type="fake_auth_success",
        ))
        return True

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------
    def session_requested(self) -> tuple:
        """Open a raw-bytes session channel + AsyncSSHShell for each channel."""
        chan = self._conn.create_server_channel(encoding=None)
        shell = AsyncSSHShell(
            session_id=self._session_id,
            source_ip=self._ip,
            username=self._username or "root",
        )
        return chan, shell


async def create_server(host="0.0.0.0", port=2222, **kwargs):
    """Create (but do not run) the AsyncSSH SSH server listener."""
    key = _load_host_key()
    server = await asyncssh.create_server(
        lambda: HoneypotSSHServer(),
        host,
        port,
        server_host_keys=[key],
        server_version=SERVER_VERSION,
        **kwargs,
    )
    return server


async def start_server(host="0.0.0.0", port=2222):
    """Run the AsyncSSH SSH server forever (used by main.py)."""
    server = await create_server(host, port)
    print(f"SSH honeypot (asyncssh) listening on port {server.get_port()}")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(start_server())