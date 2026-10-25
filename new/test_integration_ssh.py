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
import time
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


def wait_for_event(action: str, count: int, timeout: float = 5.0) -> None:
    """Wait until `count` events with this action have been logged."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = logger_mod.LOG_FILE.read_text(encoding="utf-8").splitlines()
        if sum(json.loads(l)["action"] == action for l in lines if l.strip()) >= count:
            return
        time.sleep(0.05)
    raise AssertionError(f"no {action!r} event x{count} within {timeout}s")


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
        # A clean finish reports exit status 0 (sshd does); a dropped
        # connection would leave it at -1 and the client sees a reset.
        assert chan.recv_exit_status() == 0, "exit did not report exit status 0"
        # The connection ends when the client hangs up, as with sshd.
        client.close()
        wait_for_event("connection_closed", 1)

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
        ls_event = next(e for e in events if e["action"] == "ls /etc")
        assert ls_event["parameters"]["name"] == "ls", ls_event["parameters"]
        assert ls_event["parameters"]["args"] == ["/etc"], ls_event["parameters"]

        # Adapter contract: exactly eleven top-level keys per event, and each
        # interaction logged once (no "pending" placeholder event).
        contract = {
            "event_id", "timestamp", "protocol", "source_ip", "session_id",
            "action", "parameters", "raw_metadata", "session_source",
            "response_status", "response_type",
        }
        assert all(set(e) == contract for e in events), (
            f"event schema is not the 11-key contract: {sorted(events[0])}"
        )
        assert "pending" not in resp_types, "duplicate 'pending' event logged"
        counts = {a: actions.count(a) for a in set(actions)}
        for action in ("connection_established", "login_attempt", "whoami",
                       "hacked", "exit", "connection_closed"):
            assert counts[action] == 1, f"{action} logged {counts[action]}x: {counts}"

        # --- 9) exec channel (`ssh host "cmd"`) is answered and logged ---
        # One exec per connection, like `ssh host "cmd"` from a real client.
        for cmd, expected_out, expected_rc in (
            ("uname -a", b"Linux honeypot", 0),
            ("cat /nonexistent", b"No such file or directory", 1),
        ):
            exec_client = paramiko.SSHClient()
            exec_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                exec_client.connect(
                    "127.0.0.1", port=port, username="bot", password="bot",
                    look_for_keys=False, allow_agent=False, timeout=10,
                )
                _, stdout, stderr = exec_client.exec_command(cmd, timeout=10)
                out = stdout.read() + stderr.read()
                rc = stdout.channel.recv_exit_status()
                assert expected_out in out, f"exec {cmd!r} output: {out!r}"
                assert rc == expected_rc, f"exec {cmd!r} exit status {rc}"
            finally:
                exec_client.close()

        # --- 10) several channels on ONE connection share the session ---
        multi = paramiko.SSHClient()
        multi.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            multi.connect(
                "127.0.0.1", port=port, username="mux", password="mux",
                look_for_keys=False, allow_agent=False, timeout=10,
            )

            def run(cmd):
                _, stdout, stderr = multi.exec_command(cmd, timeout=10)
                return (stdout.read() + stderr.read()).decode(), stdout.channel.recv_exit_status()

            out, rc = run("cd /etc")
            assert rc == 0, (out, rc)
            out, rc = run("pwd")  # a later channel sees the earlier one's cd
            assert out.strip() == "/etc" and rc == 0, (out, rc)
            run("export MUX_VAR=7")
            out, _ = run("printenv MUX_VAR")
            assert out.strip() == "7", out
            # An interactive shell on the same connection starts in /etc.
            shell = multi.invoke_shell()
            out = recv_until(shell, b"# ")
            assert b"root@honeypot:/etc# " in out, f"new channel prompt: {out!r}"
            shell.send(b"exit\r")
            recv_until(shell, b"logout")
            # A different connection is a different session.
            other = paramiko.SSHClient()
            other.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            other.connect(
                "127.0.0.1", port=port, username="other", password="other",
                look_for_keys=False, allow_agent=False, timeout=10,
            )
            try:
                _, stdout, _ = other.exec_command("pwd", timeout=10)
                assert stdout.read().decode().strip() == "/root", "state leaked"
            finally:
                other.close()
        finally:
            multi.close()

        events = [
            json.loads(line)
            for line in logger_mod.LOG_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        exec_events = [e for e in events if e["action"] in ("uname -a", "cat /nonexistent")]
        assert len(exec_events) == 2, f"exec commands not logged once each: {exec_events}"
        assert all(set(e) == contract for e in exec_events), "exec event breaks contract"
        cat = next(e for e in exec_events if e["action"] == "cat /nonexistent")
        assert cat["parameters"]["args"] == ["/nonexistent"], cat["parameters"]

        print("ALL SSH INTEGRATION TESTS PASSED")
    finally:
        client.close()
        tcp.shutdown()
        tcp.server_close()


if __name__ == "__main__":
    main()