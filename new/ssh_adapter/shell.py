from shared.events import build_event, command_parameters
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import decide_response
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
        # SAFETY: No real file access — the session's FakeFilesystem and shell
        # state live in the core (shared.session_state), keyed by session_id.
        self.current_dir = "/root"
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
            parameters=parameters if parameters is not None else command_parameters(cmd),
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
        response = self._decide(cmd)

        if response.response_type == "session_end":
            self.channel.send(b"\r\nlogout\r\n")
            self._log(cmd, "0", "session_end", mitre)
            self._closed = True
            return

        # Normalize \n to \r\n for PTY display
        content = response.content.replace("\n", "\r\n")
        self.channel.send(("\r\n" + content + "\r\n" + self.prompt).encode())

        # A redirected write target is intel: record it, never print it.
        params = command_parameters(cmd, response.redirect)
        self._log(cmd, response.status, response.response_type, mitre, params)

    def _decide(self, cmd: str):
        """Answer one command line through the shared decision seam."""
        # SAFETY: No subprocess/os.system — all responses via decide_response()
        # args are passed through untouched so flags and non-path operands
        # (e.g. `which bash`, `date +%Y`, `find -name ...`) are not corrupted;
        # relative paths are resolved against cwd inside the engine.
        response = decide_response(
            "ssh",
            self.session_id,
            cmd,
            {"args": parse_args(cmd), "username": self.username},
        )
        self._set_cwd(response.cwd)
        return response

    def run_exec(self, command: str) -> int:
        """Answer an exec request (`ssh host "cmd"`): no prompt, no PTY.

        The command is answered and logged exactly like an interactive one;
        the channel then reports the exit status and closes, as sshd does.
        """
        cmd = command.strip()
        mitre = mitre_analyze(cmd)
        response = self._decide(cmd)
        if response.response_type == "session_end":
            self._log(cmd, "0", "session_end", mitre)
            exit_code = 0
        else:
            if response.content:
                self.channel.sendall(response.content.encode())
            params = command_parameters(cmd, response.redirect)
            self._log(cmd, response.status, response.response_type, mitre, params)
            try:
                exit_code = int(response.status)
            except (TypeError, ValueError):
                exit_code = 0
        self.channel.send_exit_status(exit_code)
        self._closed = True
        self.channel.close()
        return exit_code

    def _set_cwd(self, cwd: str | None) -> None:
        """Mirror the session's cwd (decided by the engine) into the prompt."""
        if cwd and cwd != self.current_dir:
            self.current_dir = cwd
            self.prompt = prompt_for(self.current_dir)
