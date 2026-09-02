import os
import uuid
from datetime import datetime, timezone

from shared.logger import log_event
from shared.response_engine import decide_response
from shared.filesystem import FakeFilesystem
from shared.mitre import mitre_tag


class FakeSSHShell:
    # SAFETY: No real auth — always returns success
    def __init__(self, channel, session_id, source_ip):
        self.channel = channel
        self.session_id = session_id
        self.source_ip = source_ip
        # SAFETY: No real file access — uses FakeFilesystem
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
        # FIX: Rewrite bare "cd" BEFORE decide_response
        if cmd.strip() == "cd":
            cmd = "cd /root"

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
                "mitre_attack_id": mitre_tag(cmd),
            }
        )

        # SAFETY: No subprocess/os.system — all responses via decide_response()
        args = self._parse_args(cmd)
        resolved_args = []
        for arg in args:
            if arg.startswith("/"):
                resolved_args.append(arg)
            else:
                resolved_args.append(os.path.join(self.current_dir, arg))

        response = decide_response(
            "ssh",
            self.session_id,
            cmd,
            {"args": resolved_args, "cwd": self.current_dir},
            self.fs,
        )

        if response.response_type == "session_end":
            self.channel.send("\r\nlogout\r\n".encode())
            self._closed = True
            return

        if cmd.startswith("cd "):
            path = cmd[3:].strip()
            if not path:
                path = "/root"
            elif not path.startswith("/"):
                path = os.path.join(self.current_dir, path)

            # Normalize: /root/../etc → /etc, /root/.... → /root/....
            normalized = os.path.normpath(path)

            # Validate against FakeFilesystem
            if not self.fs.exists(normalized):
                error_msg = f"bash: cd: {path}: No such file or directory"
                self.channel.send(("\r\n" + error_msg + "\r\n" + self.prompt).encode())
                # Log the failed attempt
                log_event(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "protocol": "ssh",
                        "source_ip": self.source_ip,
                        "session_id": self.session_id,
                        "action": cmd,
                        "parameters": {"command": cmd, "target": path},
                        "raw_metadata": {},
                        "session_source": "protocol_native",
                        "response_status": "1",
                        "response_type": "cd_failed",
                        "mitre_attack_id": mitre_tag(cmd),
                    }
                )
                return
            if not self.fs.is_dir(normalized):
                error_msg = f"bash: cd: {path}: Not a directory"
                self.channel.send(("\r\n" + error_msg + "\r\n" + self.prompt).encode())
                log_event(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "protocol": "ssh",
                        "source_ip": self.source_ip,
                        "session_id": self.session_id,
                        "action": cmd,
                        "parameters": {"command": cmd, "target": path},
                        "raw_metadata": {},
                        "session_source": "protocol_native",
                        "response_status": "1",
                        "response_type": "cd_failed",
                        "mitre_attack_id": mitre_tag(cmd),
                    }
                )
                return

            self.current_dir = normalized
            self._update_prompt()

        # Normalize \n to \r\n for PTY display
        content = response.content.replace("\n", "\r\n")
        self.channel.send(("\r\n" + content + "\r\n" + self.prompt).encode())

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
                "mitre_attack_id": mitre_tag(cmd),
            }
        )

    def _parse_args(self, cmd: str) -> list:
        parts = cmd.split()
        return parts[1:] if len(parts) > 1 else []