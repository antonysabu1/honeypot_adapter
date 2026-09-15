"""What every interactive shell presents and accepts, expressed once.

Three transports answer the same fake Linux box, so the banner, the prompt, the
argument split and the keystroke handling must not drift apart between them.
Anything protocol-specific stays in the transport: telnet's IAC framing and its
own line handling, or the SSH transports' cd logging.
"""

import os
from dataclasses import dataclass

LOGIN_BANNER = "\r\nWelcome to Ubuntu 22.04 LTS\r\n\r\n"

POST_LOGIN_BANNER = (
    "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n"
    "\r\n"
    "Last login: Mon Sep  8 10:42:13 2026 from 192.168.1.100\r\n"
    "\r\n"
)

PROMPT_TEMPLATE = "root@honeypot:{path}# "


def shorten_path(path: str) -> str:
    """Present the login home as `~`, the way bash does."""
    return path.replace("/root", "~")


def prompt_for(cwd: str) -> str:
    return PROMPT_TEMPLATE.format(path=shorten_path(cwd))


def parse_args(cmd: str) -> list:
    """Split a command line into arguments, leaving flags and operands intact.

    Relative paths are resolved against the cwd inside the response engine, so
    nothing here is joined or rewritten.
    """
    parts = cmd.split()
    return parts[1:] if len(parts) > 1 else []


@dataclass
class CdResult:
    """Outcome of a `cd`.

    `path` is the path as bash echoes it and as telemetry records it — the
    target joined onto the cwd, not the raw argument.
    """

    cwd: str
    path: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def resolve_cd(target: str, cwd: str, fs) -> CdResult:
    """Resolve a `cd` target against the fake filesystem.

    The cwd is left unchanged when the move fails and `error` is the exact bash
    message to show. Callers keep their own output sink, prompt and logging —
    this is only the policy.
    """
    path = target or "/root"
    if not path.startswith("/"):
        path = os.path.join(cwd, path)
    normalized = os.path.normpath(path)
    if not fs.exists(normalized):
        return CdResult(cwd, path, f"bash: cd: {path}: No such file or directory")
    if not fs.is_dir(normalized):
        return CdResult(cwd, path, f"bash: cd: {path}: Not a directory")
    return CdResult(normalized, path)


class LineEditor:
    """Byte-level line editing for the SSH shells: echo, backspace, Ctrl+C.

    The transport supplies the output sink and the current prompt, so echo and
    command output stay interleaved exactly as typed. `on_command` is called for
    each complete line; `on_closed` lets the caller stop the loop when the
    session ended (e.g. the attacker typed `exit`).
    """

    def __init__(self, write, prompt, on_command, on_closed=lambda: False):
        self._write = write
        self._prompt = prompt
        self._on_command = on_command
        self._on_closed = on_closed
        self.buffer = b""

    def feed(self, data: bytes) -> None:
        i = 0
        while i < len(data):
            byte = data[i]

            if byte == 13:  # \r — Enter
                cmd = self.buffer.decode("utf-8", errors="ignore").strip()
                self.buffer = b""
                if cmd:
                    self._on_command(cmd)
                else:
                    self._write(("\r\n" + self._prompt()).encode())
                if i + 1 < len(data) and data[i + 1] == 10:
                    i += 1  # skip the \n of a CRLF client
            elif byte == 10:  # \n — standalone newline
                cmd = self.buffer.decode("utf-8", errors="ignore").strip()
                self.buffer = b""
                if cmd:
                    self._on_command(cmd)
                else:
                    self._write(("\r\n" + self._prompt()).encode())
            elif byte == 127:  # backspace
                if self.buffer:
                    self.buffer = self.buffer[:-1]
                    self._write(b"\b \b")
            elif byte == 3:  # Ctrl+C
                self.buffer = b""
                self._write(b"^C\r\n" + self._prompt().encode())
            elif 32 <= byte <= 126:  # printable ASCII
                self.buffer += bytes([byte])
                self._write(bytes([byte]))
            # other control bytes are ignored silently

            if self._on_closed():
                break
            i += 1
