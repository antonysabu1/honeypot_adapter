from shared.events import build_event
from shared.filesystem import FakeFilesystem
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import (
    decide_line,
    decide_response,
    has_shell_syntax,
)
from shared.shell import (
    POST_LOGIN_BANNER,
    parse_args,
    prompt_for,
    resolve_cd,
)


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
        self.prompt = prompt_for(self.current_dir)
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
            if byte == 13:  # \r — process the line (a lone CR must work too)
                line = self.buffer.decode("utf-8", errors="ignore").strip()
                self.buffer = b""
                if line:
                    self.process_line(line)
                elif self.state == "shell":
                    self.transport.write(("\r\n" + self.prompt).encode())
                # Skip a trailing \n if present (CRLF line ending)
                if i + 1 < len(buf) and buf[i + 1] == 10:
                    i += 1
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
            log_event(build_event(
                session_id=self.session_id,
                source_ip=self.source_ip,
                protocol="telnet",
                action="login_attempt",
                parameters={
                    "username": self.username,
                    "password": self.password,
                },
                response_status="authenticated",
                response_type="fake_auth_success",
                # A telnet login always "succeeds", so it is scored directly.
                mitre={
                    "mitre_attack_id": "T1078",
                    "mitre_technique_name": "Valid Accounts",
                    "mitre_tactic": "Initial Access",
                    "mitre_confidence": "high",
                },
            ))
            self.transport.write(POST_LOGIN_BANNER.encode())
            self.transport.write(self.prompt.encode())
            self.state = "shell"
        elif self.state == "shell":
            if not line:
                self.transport.write(("\r\n" + self.prompt).encode())
                return
            # Relative file paths are resolved against cwd inside decide_response()
            # via _resolve_path; args are passed through untouched so flags and
            # non-path operands (e.g. `which bash`, `date +%Y`, `find -name ...`)
            # are not corrupted by cwd-joining.
            args = parse_args(line)

            mitre = mitre_analyze(line)

            self._log(line, "0", "pending", mitre)

            # SAFETY: No subprocess/os.system — all responses via decide_response()
            # `;` / `&&` / `||` / `|` / redirection lines go to the shared line
            # path, which also resolves any `cd` segment and hands back the cwd.
            chained = has_shell_syntax(line)
            if chained:
                response, new_cwd = decide_line(
                    "telnet",
                    self.session_id,
                    line,
                    {"args": args, "cwd": self.current_dir},
                    self.fs,
                    username=self.username or "root",
                )
                if new_cwd != self.current_dir:
                    self.current_dir = new_cwd
                    self.prompt = prompt_for(self.current_dir)
            else:
                response = decide_response(
                    "telnet",
                    self.session_id,
                    line,
                    {"args": args, "cwd": self.current_dir},
                    self.fs,
                    username=self.username or "root",
                )

            if response.response_type == "session_end":
                self.transport.write(b"\r\nlogout\r\n")
                self._log(line, "0", "session_end", mitre)
                self.transport.close()
                return

            # cd (shared policy; telnet keeps its own sink and logging)
            cmd = line
            if cmd.strip() == "cd":
                cmd = "cd /root"
            if not chained and cmd.startswith("cd "):
                cd = resolve_cd(cmd[3:].strip(), self.current_dir, self.fs)
                if not cd.ok:
                    self.transport.write(
                        ("\r\n" + cd.error + "\r\n" + self.prompt).encode()
                    )
                    self._log(
                        line, "1", "cd_failed", mitre,
                        {"command": line, "target": cd.path},
                    )
                    return
                self.current_dir = cd.cwd
                self.prompt = prompt_for(self.current_dir)
                self.transport.write(("\r\n" + self.prompt).encode())
                self._log(line, "0", "command_output", mitre)
                return

            content = response.content.replace("\n", "\r\n")
            self.transport.write(("\r\n" + content + "\r\n" + self.prompt).encode())

            # A redirected write target is intel: record it, never print it.
            params = {"command": line}
            if response.redirect:
                params["redirect"] = response.redirect
            self._log(line, response.status, response.response_type, mitre, params)

    def _log(self, action: str, response_status: str, response_type: str,
             mitre: dict, parameters: dict | None = None) -> None:
        """Emit one telnet event through the canonical shared builder."""
        log_event(build_event(
            session_id=self.session_id,
            source_ip=self.source_ip,
            protocol="telnet",
            action=action,
            parameters=parameters if parameters is not None else {"command": action},
            response_status=response_status,
            response_type=response_type,
            mitre=mitre,
        ))