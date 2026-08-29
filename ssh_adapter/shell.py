import os
import uuid
from datetime import datetime, timezone

from shared.logger import log_event
from shared.response_engine import decide_response
from shared.filesystem import FakeFilesystem


class FakeSSHShell:
    def __init__(self, channel, session_id, source_ip):
        self.channel = channel
        self.session_id = session_id
        self.source_ip = source_ip
        self.fs = FakeFilesystem()
        self.current_dir = "/root"
        self.prompt = "root@honeypot:~# "
        self._closed = False

    def _shorten_path(self, path: str) -> str:
        return path.replace("/root", "~")

    def _update_prompt(self):
        self.prompt = f"root@honeypot:{self._shorten_path(self.current_dir)}# "

    def run(self):
        self.channel.send("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n".encode())
        self.channel.send(self.prompt.encode())
        buffer = b""
        while not self._closed:
            try:
                data = self.channel.recv(1024)
            except Exception:
                break
            if not data:
                break

            i = 0
            while i < len(data):
                byte = data[i]

                if byte == 13:  # \r — Enter in PTY mode
                    cmd = buffer.decode("utf-8", errors="ignore").strip()
                    buffer = b""
                    if cmd:
                        self.handle_command(cmd)
                    else:
                        self.channel.send(("\r\n" + self.prompt).encode())
                    # Skip the following \n if present (Windows/SSH clients send \r\n)
                    if i + 1 < len(data) and data[i + 1] == 10:
                        i += 1
                elif byte == 10:  # \n — standalone newline
                    cmd = buffer.decode("utf-8", errors="ignore").strip()
                    buffer = b""
                    if cmd:
                        self.handle_command(cmd)
                    else:
                        self.channel.send(("\r\n" + self.prompt).encode())
                elif byte == 127:  # backspace
                    if buffer:
                        buffer = buffer[:-1]
                        self.channel.send(b"\b \b")
                elif byte == 3:  # Ctrl+C
                    buffer = b""
                    self.channel.send(b"^C\r\n" + self.prompt.encode())
                elif 32 <= byte <= 126:  # printable ASCII
                    buffer += bytes([byte])
                    self.channel.send(bytes([byte]))
                # Ignore other control bytes silently

                i += 1

    def handle_command(self, cmd: str):
        log_event(
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protocol": "ssh",
                "source_ip": self.source_ip,
                "session_id": self.session_id,
                "action": cmd,
                "parameters": {"command": cmd},
                "raw_metadata": {},
                "session_source": "protocol_native",
                "response_status": "0",
                "response_type": "pending",
            }
        )

        response = decide_response(
            "ssh", self.session_id, cmd, {"args": self._parse_args(cmd)}, self.fs
        )

        if response.response_type == "session_end":
            self.channel.send("\r\nlogout\r\n".encode())
            self._closed = True
            return

        if cmd.startswith("cd "):
            path = cmd[3:].strip()
            if not path:
                path = "/root"
            if not path.startswith("/"):
                path = os.path.join(self.current_dir, path)
            self.current_dir = path
            self._update_prompt()

        self.channel.send(("\r\n" + response.content + "\r\n" + self.prompt).encode())

        log_event(
            {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "protocol": "ssh",
                "source_ip": self.source_ip,
                "session_id": self.session_id,
                "action": cmd,
                "parameters": {"command": cmd},
                "raw_metadata": {},
                "session_source": "protocol_native",
                "response_status": response.status,
                "response_type": response.response_type,
            }
        )

    def _parse_args(self, cmd: str) -> list:
        parts = cmd.split()
        return parts[1:] if len(parts) > 1 else []