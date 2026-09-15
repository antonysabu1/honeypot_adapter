"""Integration test: drive the AsyncSSH SSH transport with asyncssh client.

Proves the AsyncSSH adapter is a drop-in replacement for the Paramiko
transport: real SSH handshake, PTY request, interactive shell, per-command
responses from the honeypot core, exec channel, exit codes, and event
telemetry identical to the Paramiko adapter's schema.
"""

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import asyncssh

import shared.logger as logger_mod
from asyncssh_adapter.server import create_server


async def read_until(reader, marker: bytes, timeout: float = 8.0) -> bytes:
    """Read from an asyncssh SSHReader until `marker` is seen."""
    buf = b""
    deadline = time.monotonic() + timeout
    try:
        while marker not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"timeout waiting for {marker!r}; got {buf!r}"
                )
            chunk = await asyncio.wait_for(reader.read(4096), remaining)
            if not chunk:
                raise AssertionError(
                    f"EOF before marker {marker!r}; got {buf!r}"
                )
            buf += chunk
    except asyncio.TimeoutError:
        raise AssertionError(f"timeout waiting for {marker!r}; got {buf!r}")
    return buf


async def run_asyncssh_tests():
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-asyncssh-test-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"

    server = await create_server("127.0.0.1", 0)
    port = server.get_port()

    try:
        # --- 1) interactive shell with a PTY request ---
        conn = await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="alice",
            password="alice123",
            known_hosts=None,
            client_keys=None,
        )
        proc = await conn.create_process(
            term_type="xterm", term_size=(24, 80, 0, 0), encoding=None
        )

        out = await read_until(proc.stdout, b"root@honeypot:~# ")
        assert b"Welcome to Ubuntu 22.04.3 LTS" in out, f"bad banner: {out!r}"
        assert b"Documentation:  https://help.ubuntu.com" in out, "missing MOTD"

        # whoami reflects the login user
        proc.stdin.write(b"whoami\r")
        out = await read_until(proc.stdout, b"root@honeypot:~# ")
        assert b"alice" in out, f"whoami did not return login user: {out!r}"

        # cd success -> prompt updates
        proc.stdin.write(b"cd /tmp\r")
        await read_until(proc.stdout, b"root@honeypot:/tmp# ")

        # cd failure -> error + prompt unchanged
        proc.stdin.write(b"cd /nonexistent\r")
        out = await read_until(proc.stdout, b"root@honeypot:/tmp# ")
        assert b"No such file or directory" in out, f"missing cd error: {out!r}"

        # unknown command
        proc.stdin.write(b"hacked\r")
        out = await read_until(proc.stdout, b"command not found")
        assert b"bash: hacked: command not found" in out, f"bad output: {out!r}"

        # known command after cd
        proc.stdin.write(b"ls /etc\r")
        out = await read_until(proc.stdout, b"root@honeypot:/tmp# ")
        assert b"passwd" in out and b"shadow" in out, f"bad ls output: {out!r}"

        # exit -> logout + process ends
        proc.stdin.write(b"exit\r")
        out = await read_until(proc.stdout, b"logout")
        assert b"logout" in out

        conn.close()
        await asyncio.wait_for(proc.wait_closed(), 5)
        await asyncio.wait_for(conn.wait_closed(), 5)

        # --- 2) exec channel: ssh host "command" ---
        conn2 = await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="alice",
            password="alice123",
            known_hosts=None,
            client_keys=None,
        )

        result = await conn2.run("whoami")
        assert "alice" in result.stdout, f"exec whoami: {result.stdout!r}"

        result2 = await conn2.run("uname -a")
        assert "Linux honeypot 5.15.0" in result2.stdout, f"exec uname: {result2.stdout!r}"

        result3 = await conn2.run("hacked")
        assert "command not found" in result3.stdout, f"exec unknown: {result3.stdout!r}"
        assert result3.exit_status == 127, f"exec status: {result3.exit_status}"

        conn2.close()
        await asyncio.wait_for(conn2.wait_closed(), 5)

        # --- 3) public-key auth path also logs ---
        client_key = asyncssh.generate_private_key("ssh-ed25519")
        conn3 = await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="bob",
            client_keys=[client_key],
            known_hosts=None,
        )
        conn3.close()
        await asyncio.wait_for(conn3.wait_closed(), 5)

        # --- 4) events flowed through the shared logging pipeline ---
        events = [
            json.loads(line)
            for line in logger_mod.LOG_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        actions = [e["action"] for e in events]
        for expected in ("connection_established", "login_attempt",
                         "whoami", "cd /tmp", "cd /nonexistent", "hacked", "exit"):
            assert expected in actions, f"missing logged event for {expected!r}"

        resp_types = {e["response_type"] for e in events}
        for expected in ("banner_sent", "fake_auth_success", "command_output",
                         "command_not_found", "cd_failed", "session_end"):
            assert expected in resp_types, f"missing response_type {expected!r}"

        assert all(e["protocol"] == "ssh" for e in events), "non-ssh event found"

        lifecycle = [e for e in events if e["action"] == "connection_established"]
        assert lifecycle and "mitre_attack_id" in lifecycle[0], (
            "connection_established missing MITRE keys"
        )
        assert "pubkey_attempt" in actions, "missing pubkey_attempt event"

        print("ALL ASYNCSSH INTEGRATION TESTS PASSED")
        return True
    finally:
        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), 5)
        except asyncio.TimeoutError:
            pass


def main() -> None:
    asyncio.run(run_asyncssh_tests())


if __name__ == "__main__":
    main()