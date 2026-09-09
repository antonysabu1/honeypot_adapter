import os
import uuid
from datetime import datetime, timezone

from shared.logger import log_event
from shared.response_engine import decide_response
from shared.filesystem import FakeFilesystem
from shared.mitre import mitre_analyze


class TelnetSession:
    # SAFETY: No real auth — always returns success
    def __init__(self, transport, session_id, source_ip):
        self.transport = transport
        self.session_id = session_id
        self.source_ip = source_ip
        # SAFETY: No real file access — uses FakeFilesystem
        self.fs = FakeFilesystem()
        self.state = "login"
        self.username = ""
        self.password = ""
        self.current_dir = "/root"
        self.prompt = "root@honeypot:~# "
        self.buffer = b""
        self._iac_buf = b""  # leftover bytes of a partial IAC sequence
        self._sb_mode = False  # inside an IAC SB ... IAC SE subnegotiation

    def handle_data(self, data: bytes):
        """Parse telnet framing (RFC 854) and feed complete lines to the shell.

        Handles IAC commands (NOP, GA, ...), WILL/WONT/DO/DONT negotiation and
        IAC SB ... IAC SE subnegotiations — including sequences split across
        multiple TCP segments, which the previous fixed 3-byte skip could not.
        """
        buf = self._iac_buf + data
        i = 0
        while i < len(buf):
            if self._sb_mode:
                # Consume everything until IAC SE (or escaped IAC IAC).
                if buf[i] == 255:
                    if i + 1 < len(buf):
                        if buf[i + 1] == 240:  # IAC SE terminates subnegotiation
                            self._sb_mode = False
                        i += 2  # also covers IAC IAC inside the payload
                        continue
                    break  # trailing IAC — wait for the next chunk
                i += 1
                continue

            byte = buf[i]
            if byte == 255:  # IAC
                if i + 1 >= len(buf):
                    break  # incomplete sequence — wait for more data
                cmd = buf[i + 1]
                if cmd == 250:  # SB — subnegotiation begins
                    self._sb_mode = True
                    i += 2
                elif cmd in (251, 252, 253, 254):  # WILL/WONT/DO/DONT + option
                    if i + 2 >= len(buf):
                        break
                    self._handle_negotiation(cmd, buf[i + 2])
                    i += 3
                else:  # NOP, GA, IP, AO, ... — consume and ignore
                    i += 2
                continue
            if byte == 13:  # \r — ignore
                i += 1
                continue
            if byte == 10 or byte == 0:  # \n or NUL ends the line
                line = self.buffer.decode("utf-8", errors="ignore").strip()
                self.buffer = b""
                self.process_line(line)
            else:
                self.buffer += bytes([byte])
                self.transport.write(bytes([byte]))  # echo back
            i += 1
        self._iac_buf = buf[i:]

    def _handle_negotiation(self, cmd: int, option: int) -> None:
        """Reply to telnet WILL/WONT/DO/DONT so strict clients don't hang."""
        if cmd == 253:  # DO <option> — client wants us to enable it
            if option == 1:  # ECHO — we echo locally, so refuse
                self.transport.write(b"\xff\xfc\x01")  # WONT ECHO
            elif option == 3:  # SUPPRESS-GO-AHEAD
                self.transport.write(b"\xff\xfb\x03")  # WILL SGA
            else:
                self.transport.write(b"\xff\xfc" + bytes([option]))  # WONT
        elif cmd == 251:  # WILL <option> — client will enable it
            if option == 1:
                self.transport.write(b"\xff\xfd\x01")  # DO ECHO
            elif option == 3:
                self.transport.write(b"\xff\xfd\x03")  # DO SGA
            else:
                self.transport.write(b"\xff\xfe" + bytes([option]))  # DONT
        # WONT/DONT need no reply.

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
                    "mitre_attack_id": "T1078",
                    "mitre_technique_name": "Valid Accounts",
                    "mitre_tactic": "Initial Access",
                    "mitre_attack_id_secondary": None,
                    "mitre_technique_name_secondary": None,
                    "mitre_confidence": "high",
                }
            )
            motd = (
                "\r\n"
                "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n"
                "\r\n"
                " * Documentation:  https://help.ubuntu.com\r\n"
                " * Management:     https://landscape.canonical.com\r\n"
                " * Support:        https://ubuntu.com/advantage\r\n"
                "\r\n"
                "Last login: Mon Sep  8 10:42:13 2026 from 192.168.1.100\r\n"
                "\r\n"
            )
            self.transport.write(motd.encode())
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
                # Absolute paths stay untouched; flags (e.g. -la) must NOT be
                # joined to the cwd or decide_response can't recognize them.
                if arg.startswith("/") or arg.startswith("-"):
                    resolved_args.append(arg)
                else:
                    resolved_args.append(os.path.join(self.current_dir, arg))

            mitre = mitre_analyze(line)

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
                    **mitre,
                }
            )

            # SAFETY: No subprocess/os.system — all responses via decide_response()
            response = decide_response(
                "telnet",
                self.session_id,
                line,
                {"args": resolved_args, "cwd": self.current_dir},
                self.fs,
                username=self.username or "root",
            )

            if response.response_type == "session_end":
                self.transport.write(b"\r\nlogout\r\n")
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
                        "response_type": "session_end",
                        **mitre,
                    }
                )
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
                            **mitre,
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
                            **mitre,
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
                        **mitre,
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
                    **mitre,
                }
            )

    def _shorten_path(self, path: str) -> str:
        return path.replace("/root", "~")