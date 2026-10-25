from shared.events import build_event
from shared.filesystem import FakeFilesystem
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import (
    decide_line,
    decide_response,
    has_shell_syntax,
)
from shared.shell_state import VirtualShellState
from shared.shell import (
    LineEditor,
    POST_LOGIN_BANNER,
    parse_args,
    prompt_for,
)


class FakeSSHShell:
    """Paramiko transport shell.

    Everything a shell *presents* (banner, prompt, keystroke echo, cd policy)
    comes from shared.shell; this class only owns the channel it writes to and
    the telemetry it emits.
    """

    def __init__(self, channel, session_id, source_ip, username="root",
                 raw_metadata=None):
        self.channel = channel
        self.session_id = session_id
        self.source_ip = source_ip
        self.username = username or "root"
        self.raw_metadata = dict(raw_metadata or {})
        # SAFETY: No real file access — uses FakeFilesystem
        self.fs = FakeFilesystem()
        self.current_dir = "/root"
        self.shell_state = VirtualShellState(
            user=self.username or "root",
            uid=0,
            gid=0,
            groups=frozenset([0]),
            cwd="/root",
            old_pwd="/",
            home="/root",
            shell="/bin/bash",
            term="xterm-256color",
        )
        # The honeypot always presents a root shell; only whoami reflects the
        # actual login user (per session-isolation report recommendation).
        self.prompt = prompt_for(self.current_dir)
        self._closed = False
        self._editor = LineEditor(
            write=self.channel.send,
            prompt=lambda: self.prompt,
            on_command=self.handle_command,
            on_closed=lambda: self._closed,
        )

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------
    def _log(self, cmd: str, response_status: str, response_type: str,
             mitre: dict, parameters: dict | None = None):
        log_event(build_event(
            session_id=self.session_id,
            source_ip=self.source_ip,
            protocol="ssh",
            action=cmd,
            parameters=parameters if parameters is not None else {"command": cmd},
            response_status=response_status,
            response_type=response_type,
            mitre=mitre,
            raw_metadata=self.raw_metadata,
        ))

    # ------------------------------------------------------------------
    # Session loop
    # ------------------------------------------------------------------
    def run(self):
        self.channel.send(POST_LOGIN_BANNER.encode())
        self.channel.send(self.prompt.encode())

        while not self._closed:
            try:
                data = self.channel.recv(1024)
            except Exception:
                break
            if not data:
                break
            self._editor.feed(data)

    def handle_command(self, cmd: str):
        mitre = mitre_analyze(cmd)

        # SAFETY: No subprocess/os.system — all responses via decide_response()
        # args are passed through untouched so flags and non-path operands
        # (e.g. `which bash`, `date +%Y`, `find -name ...`) are not corrupted;
        # relative paths are resolved against cwd inside the engine.
        args = parse_args(cmd)

        # `;` / `&&` / `||` / `|` / redirection lines go to the shared line path,
        # which also resolves any `cd` segment and hands back the resulting cwd.
        chained = has_shell_syntax(cmd)
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
                shell_state=self.shell_state,
            )
            # `cd` mutates the session's shell state inside the one decision
            # seam; the transport only mirrors the resulting cwd into its prompt.
            self._sync_cwd()

        if response.response_type == "session_end":
            self.channel.send(b"\r\nlogout\r\n")
            self._log(cmd, "0", "session_end", mitre)
            self._closed = True
            return

        # Normalize \n to \r\n for PTY display
        content = response.content.replace("\n", "\r\n")
        self.channel.send(("\r\n" + content + "\r\n" + self.prompt).encode())

        # A redirected write target is intel: record it, never print it.
        params = {"command": cmd}
        if response.redirect:
            params["redirect"] = response.redirect
        self._log(cmd, response.status, response.response_type, mitre, params)

    def _apply_cwd(self, new_cwd: str) -> None:
        if new_cwd != self.current_dir:
            old_cwd = self.current_dir
            self.current_dir = new_cwd
            self.prompt = prompt_for(self.current_dir)
            self.shell_state.cwd = new_cwd
            self.shell_state.old_pwd = old_cwd
            self.shell_state.set_env('PWD', new_cwd)
            self.shell_state.set_env('OLDPWD', old_cwd)

    def _sync_cwd(self) -> None:
        """Mirror a cwd change made by decide_response() into the prompt."""
        if self.shell_state.cwd != self.current_dir:
            self.current_dir = self.shell_state.cwd
            self.prompt = prompt_for(self.current_dir)
