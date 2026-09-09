"""Integration test: drive the real SSH honeypot adapter via paramiko.

Starts the actual ThreadingTCPServer + SSHHandler on an ephemeral loopback
port, connects with a real paramiko client, and exercises: login, cd (success
+ failure), unknown command, directory listing, and exit. Also verifies the
events the adapter writes through shared.logger.
"""

import json
import os
import socketserver
import sys
import tempfile
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import paramiko

import shared.logger as logger_mod
from ssh_adapter.server import SSHHandler


def recv_until(chan: paramiko.Channel, marker: bytes, timeout: float = 8.0) -> bytes:
    """Read from a channel until `marker` is seen. Returns everything received."""
    chan.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = chan.recv(4096)
        if not chunk:
            raise AssertionError(
                f"channel closed before marker {marker!r}; got {buf!r}"
            )
        buf += chunk
    return buf


def main() -> None:
    # Redirect honeypot logging to a temp file so the test never touches the
    # real logs/honeypot.jsonl. log_event() resolves these globals at call time.
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-ssh-test-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"

    # Start the real SSH server on an ephemeral port (no fixed-port conflicts).
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SSHHandler)
    tcp.allow_reuse_address = True
    tcp.daemon_threads = True
    port = tcp.server_address[1]
    threading.Thread(target=tcp.serve_forever, daemon=True).start()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # --- 1) Login: handshake + fake password auth + shell prompt ---
        client.connect(
            "127.0.0.1",
            port=port,
            username="alice",
            password="alice123",
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )
        chan = client.invoke_shell()
        out = recv_until(chan, b"root@honeypot:~# ")
        assert b"Welcome to Ubuntu 22.04.3 LTS" in out, f"bad banner: {out!r}"
        assert b"Documentation:  https://help.ubuntu.com" in out, "missing MOTD"

        # --- 2) whoami reflects the login user, not hardcoded root ---
        chan.send(b"whoami\r")
        out = recv_until(chan, b"root@honeypot:~# ")
        assert b"alice" in out, f"whoami did not return login user: {out!r}"

        # --- 3) cd success: prompt must update ---
        chan.send(b"cd /tmp\r")
        recv_until(chan, b"root@honeypot:/tmp# ")

        # --- 4) cd failure: error + prompt unchanged ---
        chan.send(b"cd /nonexistent\r")
        out = recv_until(chan, b"root@honeypot:/tmp# ")
        assert b"No such file or directory" in out, f"missing cd error: {out!r}"

        # --- 5) unknown command -> command not found ---
        chan.send(b"hacked\r")
        out = recv_until(chan, b"command not found")
        assert b"bash: hacked: command not found" in out, f"bad output: {out!r}"

        # --- 6) known command after cd ---
        chan.send(b"ls /etc\r")
        out = recv_until(chan, b"root@honeypot:/tmp# ")
        assert b"passwd" in out and b"shadow" in out, f"bad ls output: {out!r}"

        # --- 7) exit -> logout + channel reaches EOF ---
        chan.send(b"exit\r")
        out = recv_until(chan, b"logout")
        assert b"logout" in out
        chan.settimeout(5)
        assert chan.recv(4096) == b"", "channel did not close after exit"

        # --- 8) events flowed through the shared logging pipeline ---
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
        assert all(e["protocol"] == "ssh" for e in events), "non-ssh event found"
        # Lifecycle events must carry the MITRE keys (null values) for schema
        # consistency, per the attack-graph / detection-coverage reports.
        lifecycle = [e for e in events if e["action"] == "connection_established"]
        assert lifecycle and "mitre_attack_id" in lifecycle[0], (
            "connection_established missing MITRE keys"
        )

        print("ALL SSH INTEGRATION TESTS PASSED")
    finally:
        client.close()
        tcp.shutdown()
        tcp.server_close()


if __name__ == "__main__":
    main()