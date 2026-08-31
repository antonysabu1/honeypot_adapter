import os
import uuid
from datetime import datetime, timezone

from shared.logger import log_event
from shared.response_engine import decide_response
from shared.filesystem import FakeFilesystem


class TelnetSession:
    def __init__(self, transport, session_id, source_ip):
        self.transport = transport
        self.session_id = session_id
        self.source_ip = source_ip
        self.fs = FakeFilesystem()
        self.state = "login"
        self.username = ""
        self.password = ""
        self.current_dir = "/root"
        self.prompt = "root@honeypot:~# "
        self.buffer = b""

    def handle_data(self, data: bytes):
        i = 0
        while i < len(data):
            byte = data[i]
            if byte == 255:  # IAC — skip 2 more bytes (3-byte sequence)
                i += 3
                continue
            if byte == 13:  # \r — ignore
                i += 1
                continue
            if byte == 10 or byte == 0:  # \n or NUL
                line = self.buffer.decode("utf-8", errors="ignore").strip()
                self.buffer = b""
                self.process_line(line)
            else:
                self.buffer += bytes([byte])
                self.transport.write(bytes([byte]))  # echo back
            i += 1

    def process_line(self, line: str):
        if self.state == "login":
            self.username = line
            self.transport.write(b"\r\nPassword: ")
            self.state = "password"
        elif self.state == "password":
            self.password = line
            log_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "protocol": "telnet",
                    "source_ip": self.source_ip,
                    "session_id": self.session_id,
                    "action": "login_attempt",
                    "parameters": {
                        "username": self.username,
                        "password": self.password,
                    },
                    "raw_metadata": {},
                    "session_source": "protocol_native",
                    "response_status": "authenticated",
                    "response_type": "fake_auth_success",
                }
            )
            self.transport.write(b"\r\n\r\n")
            self.transport.write(self.prompt.encode())
            self.state = "shell"
        elif self.state == "shell":
            if not line:
                self.transport.write(("\r\n" + self.prompt).encode())
                return
            # Resolve relative paths for cat/ls
            args = line.split()[1:] if len(line.split()) > 1 else []
            resolved_args = []
            for arg in args:
                if arg.startswith("/"):
                    resolved_args.append(arg)
                else:
                    resolved_args.append(os.path.join(self.current_dir, arg))

            log_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "protocol": "telnet",
                    "source_ip": self.source_ip,
                    "session_id": self.session_id,
                    "action": line,
                    "parameters": {"command": line},
                    "raw_metadata": {},
                    "session_source": "protocol_native",
                    "response_status": "0",
                    "response_type": "pending",
                }
            )

            response = decide_response(
                "telnet",
                self.session_id,
                line,
                {"args": resolved_args, "cwd": self.current_dir},
                self.fs,
            )

            if response.response_type == "session_end":
                self.transport.write(b"\r\nlogout\r\n")
                self.transport.close()
                return

            # Handle cd locally (same logic as SSH shell)
            cmd = line
            if cmd.strip() == "cd":
                cmd = "cd /root"
            if cmd.startswith("cd "):
                path = cmd[3:].strip()
                if not path:
                    path = "/root"
                elif not path.startswith("/"):
                    path = os.path.join(self.current_dir, path)
                normalized = os.path.normpath(path)
                if not self.fs.exists(normalized):
                    error = f"bash: cd: {path}: No such file or directory"
                    self.transport.write(
                        ("\r\n" + error + "\r\n" + self.prompt).encode()
                    )
                    log_event(
                        {
                            "event_id": str(uuid.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "protocol": "telnet",
                            "source_ip": self.source_ip,
                            "session_id": self.session_id,
                            "action": line,
                            "parameters": {"command": line, "target": path},
                            "raw_metadata": {},
                            "session_source": "protocol_native",
                            "response_status": "1",
                            "response_type": "cd_failed",
                        }
                    )
                    return
                if not self.fs.is_dir(normalized):
                    error = f"bash: cd: {path}: Not a directory"
                    self.transport.write(
                        ("\r\n" + error + "\r\n" + self.prompt).encode()
                    )
                    log_event(
                        {
                            "event_id": str(uuid.uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "protocol": "telnet",
                            "source_ip": self.source_ip,
                            "session_id": self.session_id,
                            "action": line,
                            "parameters": {"command": line, "target": path},
                            "raw_metadata": {},
                            "session_source": "protocol_native",
                            "response_status": "1",
                            "response_type": "cd_failed",
                        }
                    )
                    return
                self.current_dir = normalized
                self.prompt = (
                    f"root@honeypot:{self._shorten_path(self.current_dir)}# "
                )
                self.transport.write(("\r\n" + self.prompt).encode())
                log_event(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "protocol": "telnet",
                        "source_ip": self.source_ip,
                        "session_id": self.session_id,
                        "action": line,
                        "parameters": {"command": line},
                        "raw_metadata": {},
                        "session_source": "protocol_native",
                        "response_status": "0",
                        "response_type": "command_output",
                    }
                )
                return

            content = response.content.replace("\n", "\r\n")
            self.transport.write(("\r\n" + content + "\r\n" + self.prompt).encode())
            log_event(
                {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "protocol": "telnet",
                    "source_ip": self.source_ip,
                    "session_id": self.session_id,
                    "action": line,
                    "parameters": {"command": line},
                    "raw_metadata": {},
                    "session_source": "protocol_native",
                    "response_status": response.status,
                    "response_type": response.response_type,
                }
            )

    def _shorten_path(self, path: str) -> str:
        return path.replace("/root", "~")