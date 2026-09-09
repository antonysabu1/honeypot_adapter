"""Integration test: drive the real Telnet honeypot adapter over a TCP socket.

Starts the actual asyncio TelnetServer on an ephemeral loopback port, connects
with a plain socket, and exercises: login, cd (success + failure), unknown
command, file read, and exit. Also verifies the events the adapter writes
through shared.logger.
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import shared.logger as logger_mod
from telnet_adapter.server import TelnetServer


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 8.0) -> bytes:
    """Read from a socket until `marker` is seen. Returns everything received."""
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(
                f"socket closed before marker {marker!r}; got {buf!r}"
            )
        buf += chunk
    return buf


def connect_with_retry(port: int, timeout: float = 10.0) -> socket.socket:
    """Connect, retrying until the server is accepting (first connect = login test)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def main() -> None:
    # Redirect honeypot logging to a temp file so the test never touches the
    # real logs/honeypot.jsonl. log_event() resolves these globals at call time.
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-telnet-test-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"

    # Start the real TelnetServer on an ephemeral port (no fixed-port conflicts).
    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(
        loop.create_server(TelnetServer, "127.0.0.1", 0)
    )
    port = server.sockets[0].getsockname()[1]
    loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
    loop_thread.start()

    sock = None
    try:
        sock = connect_with_retry(port)

        # --- 1) Login: banner -> login: -> Password: -> shell prompt ---
        out = recv_until(sock, b"login: ")
        assert b"Welcome to Ubuntu 22.04 LTS" in out, f"bad banner: {out!r}"

        # --- 2) IAC negotiation (RFC 854): DO ECHO must be refused with WONT
        # ECHO, and an SB ... SE subnegotiation must not desync the stream.
        # Sent together with the credential lines so the replies are guaranteed
        # to precede the next prompt (same data_received pass). ---
        sock.sendall(b"\xff\xfd\x01" + b"admin\r\n")  # IAC DO ECHO + username
        out = recv_until(sock, b"Password: ")
        assert b"\xff\xfc\x01" in out, "server did not reply WONT ECHO to DO ECHO"
        sock.sendall(b"\xff\xfa\x18\x01\xff\xf0" + b"secret\r\n")  # IAC SB TTYPE SEND
        out = recv_until(sock, b"root@honeypot:~# ")
        assert b"Welcome to Ubuntu 22.04.3 LTS" in out, "missing MOTD after login"

        # --- 3) whoami reflects the login user, not hardcoded root ---
        sock.sendall(b"whoami\r\n")
        out = recv_until(sock, b"root@honeypot:~# ")
        assert b"admin" in out, f"whoami did not return login user: {out!r}"

        # --- 4) cd success: prompt must update ---
        sock.sendall(b"cd /tmp\r\n")
        recv_until(sock, b"root@honeypot:/tmp# ")

        # --- 5) cd failure: error + prompt unchanged ---
        sock.sendall(b"cd /nonexistent\r\n")
        out = recv_until(sock, b"root@honeypot:/tmp# ")
        assert b"No such file or directory" in out, f"missing cd error: {out!r}"

        # --- 6) unknown command -> command not found ---
        sock.sendall(b"hacked\r\n")
        out = recv_until(sock, b"command not found")
        assert b"bash: hacked: command not found" in out, f"bad output: {out!r}"

        # --- 7) known command after cd ---
        sock.sendall(b"cat /etc/hosts\r\n")
        out = recv_until(sock, b"root@honeypot:/tmp# ")
        assert b"127.0.0.1 localhost" in out, f"bad cat output: {out!r}"
        assert b"127.0.1.1 honeypot" in out

        # --- 8) exit -> logout + server closes the connection ---
        sock.sendall(b"exit\r\n")
        out = recv_until(sock, b"logout")
        assert b"logout" in out
        sock.settimeout(5)
        assert sock.recv(4096) == b"", "server did not close connection after exit"

        # --- 9) events flowed through the shared logging pipeline ---
        events = [
            json.loads(line)
            for line in logger_mod.LOG_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        actions = [e["action"] for e in events]
        for expected in ("login_attempt", "cd /tmp", "cd /nonexistent", "hacked", "exit"):
            assert expected in actions, f"missing logged event for {expected!r}"
        resp_types = {e["response_type"] for e in events}
        assert "fake_auth_success" in resp_types, "no fake_auth_success event"
        assert "cd_failed" in resp_types, "no cd_failed event"
        assert "command_not_found" in resp_types, "no command_not_found event"
        assert "session_end" in resp_types, "no session_end event for exit"
        assert all(e["protocol"] == "telnet" for e in events), "non-telnet event found"
        # Login events must carry MITRE keys (null for lifecycle, T1078 for auth).
        login_events = [e for e in events if e["action"] == "login_attempt"]
        assert login_events and login_events[0]["mitre_attack_id"] == "T1078", (
            "login_attempt missing T1078 tag"
        )

        print("ALL TELNET INTEGRATION TESTS PASSED")
    finally:
        if sock is not None:
            sock.close()
        loop.call_soon_threadsafe(loop.stop)
        loop_thread.join(timeout=5)
        loop.close()


if __name__ == "__main__":
    main()