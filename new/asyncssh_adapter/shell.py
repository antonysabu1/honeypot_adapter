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

import asyncssh

from shared.events import build_event
from shared.filesystem import FakeFilesystem
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import decide_line, decide_response, is_chained
from shared.shell import (
    LineEditor,
    POST_LOGIN_BANNER,
    parse_args,
    prompt_for,
    resolve_cd,
)


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
        self.prompt = prompt_for(self.current_dir)
        self._chan = None
        self._exec_command = None
        self._closed = False
        self._editor = LineEditor(
            write=self._write,
            prompt=lambda: self.prompt,
            on_command=self.handle_command,
            on_closed=lambda: self._closed,
        )

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
        self._editor.feed(data)

    def eof_received(self) -> bool:
        self._shutdown_silent()
        return False

    def connection_lost(self, exc) -> None:
        self._closed = True

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Command handling (shared with ssh_adapter/shell.py via shared.shell)
    # ------------------------------------------------------------------
    def handle_command(self, cmd: str) -> None:
        if cmd.strip() == "cd":  # rewrite bare cd before decide_response
            cmd = "cd /root"

        mitre = mitre_analyze(cmd)

        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd}, "0", "pending", mitre=mitre,
        ))

        args = parse_args(cmd)

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
            self._apply_cwd(new_cwd)
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

    def _apply_cwd(self, new_cwd: str) -> None:
        if new_cwd != self.current_dir:
            self.current_dir = new_cwd
            self.prompt = prompt_for(self.current_dir)

    def _handle_cd(self, cmd: str, mitre: dict) -> bool | None:
        """Handle 'cd <path>': returns True when handled (success or failure)."""
        result = resolve_cd(cmd[3:].strip(), self.current_dir, self.fs)
        if result.ok:
            self._apply_cwd(result.cwd)
            return None

        self._write(("\r\n" + result.error + "\r\n" + self.prompt).encode())
        log_event(build_event(
            self.session_id, self.source_ip, "ssh", cmd,
            {"command": cmd, "target": result.path}, "1", "cd_failed", mitre=mitre,
        ))
        return True

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

        args = parse_args(cmd)
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
        self._write(POST_LOGIN_BANNER.encode())
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