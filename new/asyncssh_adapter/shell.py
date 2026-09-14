"""AsyncSSH session handler: interactive shell + exec channel.

This is the transport-specific half of the honeypot. All command processing
is delegated unchanged to the honeypot core:

    shared.response_engine.decide_response
    shared.filesystem.FakeFilesystem
    shared.mitre.mitre_analyze
    shared.logger.log_event

SAFETY: No subprocess / os.system / eval / pty.spawn anywhere. Every command
is answered by the simulated response engine; nothing is ever executed.

The behaviour (banner, prompt, line handling, event schema, cd handling,
error strings) intentionally mirrors ssh_adapter/shell.py so the two SSH
transports are interchangeable.
"""

import os

import asyncssh

from asyncssh_adapter.events import build_event
from shared.filesystem import FakeFilesystem
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import decide_line, decide_response, is_chained


class AsyncSSHShell(asyncssh.SSHServerSession):
    """One interactive shell or exec invocation on an SSH transport.

    A fresh instance is created per session channel
    (session_requested() -> AsyncSSHShell) and is fully discarded on close,
    so state never leaks between clients.
    """

    def __init__(self, session_id: str, source_ip: str, username: str = "root"):
        self.session_id = session_id
        self.source_ip = source_ip
        self.username = username or "root"
        self.fs = FakeFilesystem()
        self.current_dir = "/root"
        self.prompt = "root@honeypot:~# "
        self._chan = None
        self._exec_command = None
        self._buffer = b""
        self._closed = False

    # ------------------------------------------------------------------
    # AsyncSSH session wiring
    # ------------------------------------------------------------------
    def connection_made(self, chan: "asyncssh.SSHServerChannel") -> None:
        self._chan = chan

    def pty_requested(self, term_type, term_size, term_modes) -> bool:
        return True

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        self._exec_command = command
        return True

    def session_started(self) -> None:
        if self._exec_command is not None:
            self._run_exec(self._exec_command)
        else:
            self._send_motd()

    def data_received(self, data: bytes, datatype) -> None:
        if self._closed or not data:
            return
        buf = self._buffer + data
        self._buffer = self._process_bytes(buf)
        if self._closed:
            return

    def eof_received(self) -> bool:
        self._shutdown_silent()
        return False

    def connection_lost(self, exc) -> None:
        self._closed = True

    # ------------------------------------------------------------------
    # Byte-level line loop (mirrors FakeSSHShell.run)
    # ------------------------------------------------------------------
    def _process_bytes(self, data: bytes) -> bytes:
        """Process a chunk of interactive input; returns the leftover buffer."""
        i = 0
        buffer = b""
        while i < len(data):
            byte = data[i]

            if byte == 13:  # \r — Enter
                cmd = buffer.decode("utf-8", errors="ignore").strip()
                buffer = b""
                if cmd:
                    self.handle_command(cmd)
                else:
                    self._write(("\r\n" + self.prompt).encode())
                if i + 1 < len(data) and data[i + 1] == 10:
                    i += 1  # skip following \n (CRLF clients)
            elif byte == 10:  # \n — standalone newline
                cmd = buffer.decode("utf-8", errors="ignore").strip()
                buffer = b""
                if cmd:
                    self.handle_command(cmd)
                else:
                    self._write(("\r\n" + self.prompt).encode())
            elif byte == 127:  # backspace
                if buffer:
                    buffer = buffer[:-1]
                    self._write(b"\b \b")
            elif byte == 3:  # Ctrl+C
                buffer = b""
                self._write(b"^C\r\n" + self.prompt.encode())
            elif 32 <= byte <= 126:  # printable ASCII
                buffer += bytes([byte])
                self._write(bytes([byte]))
            # other control bytes are ignored silently (same as FakeSSHShell)

            if self._closed:
                break
            i += 1
        return buffer

    # ------------------------------------------------------------------
    # Command handling (mirrors FakeSSHShell.handle_command)
    # ------------------------------------------------------------------
    def handle_command(self, cmd: str) -> None:
        if cmd.strip() == "cd":  # rewrite bare cd before decide_response
            cmd = "cd /root"

        mitre = mitre_analyze(cmd)

        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd}, "0", "pending", mitre=mitre,
        ))

        args = self._parse_args(cmd)

        # `;` / `&&` / `||` lines go to the shared sequencer, which also resolves
        # any `cd` segment and hands back the resulting cwd.
        chained = is_chained(cmd)
        if chained:
            response, new_cwd = decide_line(
                "ssh",
                self.session_id,
                cmd,
                {"args": args, "cwd": self.current_dir},
                self.fs,
                username=self.username,
            )
            if new_cwd != self.current_dir:
                self.current_dir = new_cwd
                self._update_prompt()
        else:
            response = decide_response(
                "ssh",
                self.session_id,
                cmd,
                {"args": args, "cwd": self.current_dir},
                self.fs,
                username=self.username,
            )

        if response.response_type == "session_end":
            self._write(b"\r\nlogout\r\n")
            log_event(build_event(
                self.session_id, self.source_ip, "ssh", cmd,
                {"command": cmd}, "0", "session_end", mitre=mitre,
            ))
            self._exit_session(0)
            return

        if not chained and cmd.startswith("cd "):
            handled = self._handle_cd(cmd, mitre)
            if handled is not None:
                return

        content = response.content.replace("\n", "\r\n")
        self._write(("\r\n" + content + "\r\n" + self.prompt).encode())

        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd}, response.status, response.response_type,
            mitre=mitre,
        ))

    def _handle_cd(self, cmd: str, mitre: dict) -> bool | None:
        """Handle 'cd <path>': returns True when handled (success or failure)."""
        path = cmd[3:].strip()
        if not path:
            path = "/root"
        elif not path.startswith("/"):
            path = os.path.join(self.current_dir, path)

        normalized = os.path.normpath(path)

        if not self.fs.exists(normalized):
            error_msg = f"bash: cd: {path}: No such file or directory"
            self._write(("\r\n" + error_msg + "\r\n" + self.prompt).encode())
            log_event(build_event(
                self.session_id, self.source_ip, "ssh", cmd,
                {"command": cmd, "target": path}, "1", "cd_failed", mitre=mitre,
            ))
            return True
        if not self.fs.is_dir(normalized):
            error_msg = f"bash: cd: {path}: Not a directory"
            self._write(("\r\n" + error_msg + "\r\n" + self.prompt).encode())
            log_event(build_event(
                self.session_id, self.source_ip, "ssh", cmd,
                {"command": cmd, "target": path}, "1", "cd_failed", mitre=mitre,
            ))
            return True

        self.current_dir = normalized
        self._update_prompt()
        return None

    def _update_prompt(self) -> None:
        self.prompt = f"root@honeypot:{self._shorten_path(self.current_dir)}# "

    def _shorten_path(self, path: str) -> str:
        return path.replace("/root", "~")

    def _parse_args(self, cmd: str) -> list:
        parts = cmd.split()
        return parts[1:] if len(parts) > 1 else []

    # ------------------------------------------------------------------
    # Exec channel (ssh host "command")
    # ------------------------------------------------------------------
    def _run_exec(self, command: str) -> None:
        cmd = command.strip()
        mitre = mitre_analyze(cmd)

        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd}, "0", "pending", mitre=mitre,
        ))

        args = self._parse_args(cmd)
        if is_chained(cmd):
            response, self.current_dir = decide_line(
                "ssh",
                self.session_id,
                cmd,
                {"args": args, "cwd": self.current_dir},
                self.fs,
                username=self.username,
            )
        else:
            response = decide_response(
                "ssh",
                self.session_id,
                cmd,
                {"args": args, "cwd": self.current_dir},
                self.fs,
                username=self.username,
            )

        if response.response_type == "session_end":
            response = None  # `exit` as an exec: no output, exit 0

        if response is not None and response.content:
            self._write(response.content.encode())

        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd}, response.status if response else "0",
            response.response_type if response else "command_output",
            mitre=mitre,
        ))

        try:
            exit_code = int(response.status) if response else 0
        except (TypeError, ValueError):
            exit_code = 0
        self._exit_session(exit_code)

    # ------------------------------------------------------------------
    # Output / shutdown
    # ------------------------------------------------------------------
    def _send_motd(self) -> None:
        self._write(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n")
        motd = (
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n\r\n"
            "Last login: Mon Sep  8 10:42:13 2026 from 192.168.1.100\r\n\r\n"
        )
        self._write(motd.encode())
        self._write(self.prompt.encode())

    def _write(self, data: bytes) -> None:
        if self._chan is not None and not self._closed:
            self._chan.write(data)

    def _exit_session(self, status: int) -> None:
        self._closed = True
        if self._chan is not None:
            self._chan.exit(status)

    def _shutdown_silent(self) -> None:
        if not self._closed:
            self._closed = True
            if self._chan is not None:
                self._chan.close()