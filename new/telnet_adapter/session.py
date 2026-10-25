from shared.events import build_event
from shared.logger import log_event
from shared.mitre import mitre_analyze
from shared.response_engine import decide_response
from shared.shell import (
    POST_LOGIN_BANNER,
    parse_args,
    prompt_for,
)


class TelnetSession:
    # SAFETY: No real auth — always returns success
    def __init__(self, transport, session_id, source_ip):
        self.transport = transport
        self.session_id = session_id
        self.source_ip = source_ip
        # SAFETY: No real file access — the session's FakeFilesystem and shell
        # state live in the core (shared.session_state), keyed by session_id.
        self.state = "login"
        self.username = ""
        self.password = ""
        self.current_dir = "/root"
        self.prompt = prompt_for(self.current_dir)
        self.buffer = b""
        self._iac_buf = b""  # leftover bytes of a partial IAC sequence
        self._sb_mode = False  # inside an IAC SB ... IAC SE subnegotiation
        self._sb_option = None
        self._sb_payload = bytearray()
        self.term_type = None
        # The server announces WILL ECHO + WILL SGA on connect (as telnetd
        # does), so the client stops echoing locally and we echo instead —
        # which is what lets the password be typed without being shown.
        self._will_echo = True
        self._after_cr = False  # last data byte was CR (pairs with LF/NUL)

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
                # Collect the payload until IAC SE; IAC IAC is a literal 255.
                byte = buf[i]
                if byte == 255:
                    if i + 1 >= len(buf):
                        break  # trailing IAC — wait for the next chunk
                    nxt = buf[i + 1]
                    if nxt == 240:  # IAC SE terminates subnegotiation
                        self._handle_subnegotiation(
                            self._sb_option, bytes(self._sb_payload)
                        )
                        self._sb_mode = False
                        self._sb_option = None
                        self._sb_payload = bytearray()
                        i += 2
                    elif nxt == 255:  # escaped IAC inside the payload
                        self._sb_payload.append(255)
                        i += 2
                    else:  # IAC command inside SB — consume and ignore
                        i += 2
                    continue
                self._sb_payload.append(byte)
                i += 1
                continue

            byte = buf[i]
            if byte == 255:  # IAC
                if i + 1 >= len(buf):
                    break  # incomplete sequence — wait for more data
                cmd = buf[i + 1]
                if cmd == 250:  # SB — subnegotiation begins
                    if i + 2 >= len(buf):
                        break  # wait for the subnegotiation option byte
                    self._sb_mode = True
                    self._sb_option = buf[i + 2]
                    self._sb_payload = bytearray()
                    i += 3
                elif cmd in (251, 252, 253, 254):  # WILL/WONT/DO/DONT + option
                    if i + 2 >= len(buf):
                        break
                    self._handle_negotiation(cmd, buf[i + 2])
                    i += 3
                else:  # NOP, GA, IP, AO, ... — consume and ignore
                    i += 2
                continue
            if byte == 13:  # CR ends the line (RFC 854: CR LF or CR NUL)
                self._end_line()
                self._after_cr = True
                i += 1
                continue
            if byte in (10, 0):
                if self._after_cr:
                    # Second half of CR LF / CR NUL, possibly in a later
                    # segment: the line already ended at the CR.
                    self._after_cr = False
                elif byte == 10:  # a bare LF (e.g. netcat) also ends a line
                    self._end_line()
                # A bare NUL is a no-op.
                i += 1
                continue
            self._after_cr = False
            if byte in (8, 127):  # BS / DEL — erase one character
                if self.buffer:
                    # Drop a whole UTF-8 character, not just its last byte.
                    end = len(self.buffer) - 1
                    while end > 0 and (self.buffer[end] & 0xC0) == 0x80:
                        end -= 1
                    self.buffer = self.buffer[:end]
                    self._echo(b"\b \b")
            elif byte == 3:  # Ctrl-C in character mode — abandon the line
                self.buffer = b""
                if self.state == "shell":
                    self.transport.write(("^C\r\n" + self.prompt).encode())
            else:
                self.buffer += bytes([byte])
                self._echo(bytes([byte]))
            i += 1
        self._iac_buf = buf[i:]

    def _end_line(self) -> None:
        line = self.buffer.decode("utf-8", errors="ignore").strip()
        self.buffer = b""
        if line or self.state == "password":  # an empty password is valid
            self.process_line(line)
        elif self.state == "login":
            self.transport.write(b"\r\nlogin: ")
        elif self.state == "shell":
            self.transport.write(("\r\n" + self.prompt).encode())

    def _echo(self, data: bytes) -> None:
        """Echo typed input, except while the password is being entered."""
        if self._will_echo and self.state != "password":
            self.transport.write(data)

    def _handle_negotiation(self, cmd: int, option: int) -> None:
        """Reply to telnet WILL/WONT/DO/DONT so strict clients don't hang.

        Options we already announced are not acknowledged again (RFC 854:
        only a change of state is answered), which keeps negotiation loop-free.
        """
        if cmd == 253:  # DO <option> — client wants us to enable it
            if option == 1:  # ECHO — server-side echo
                if not self._will_echo:
                    self._will_echo = True
                    self.transport.write(b"\xff\xfb\x01")  # WILL ECHO
            elif option == 3:  # SUPPRESS-GO-AHEAD — announced on connect
                pass
            else:
                self.transport.write(b"\xff\xfc" + bytes([option]))  # WONT
        elif cmd == 254:  # DONT <option>
            if option == 1 and self._will_echo:
                # The client insists on local echo; stop echoing ourselves.
                self._will_echo = False
                self.transport.write(b"\xff\xfc\x01")  # WONT ECHO
        elif cmd == 251:  # WILL <option> — client will enable it
            if option == 3:
                self.transport.write(b"\xff\xfd\x03")  # DO SGA
            elif option == 24:  # TERMINAL-TYPE — ask for the client's value
                self.transport.write(b"\xff\xfa\x18\x01\xff\xf0")  # SB TTYPE SEND
            else:  # includes WILL ECHO: the client must not echo our output
                self.transport.write(b"\xff\xfe" + bytes([option]))  # DONT
        # WONT needs no reply.

    def _handle_subnegotiation(self, option, payload: bytes) -> None:
        """Record useful subnegotiation values (currently TERMINAL-TYPE)."""
        if option == 24 and payload and payload[0] == 0:  # TTYPE IS <value>
            term = payload[1:].decode("ascii", errors="ignore").strip()
            if term:
                self.term_type = term[:64]

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
                raw_metadata=self._raw_metadata(),
            ))
            self.transport.write(POST_LOGIN_BANNER.encode())
            self.transport.write(self.prompt.encode())
            self.state = "shell"
        elif self.state == "shell":
            if not line:
                self.transport.write(("\r\n" + self.prompt).encode())
                return
            mitre = mitre_analyze(line)

            # SAFETY: No subprocess/os.system — all responses via decide_response(),
            # the one decision seam for plain and `;` / `|` / redirection lines.
            # Relative file paths are resolved against cwd inside the engine;
            # args are passed through untouched so flags and non-path operands
            # (e.g. `which bash`, `date +%Y`, `find -name ...`) are not corrupted.
            response = decide_response(
                "telnet",
                self.session_id,
                line,
                {"args": parse_args(line), "username": self.username or "root"},
            )
            if response.cwd and response.cwd != self.current_dir:
                self.current_dir = response.cwd
                self.prompt = prompt_for(self.current_dir)

            if response.response_type == "session_end":
                self.transport.write(b"\r\nlogout\r\n")
                self._log(line, "0", "session_end", mitre)
                self.transport.close()
                return

            content = response.content.replace("\n", "\r\n")
            self.transport.write(("\r\n" + content + "\r\n" + self.prompt).encode())

            # A redirected write target is intel: record it, never print it.
            params = {"command": line}
            if response.redirect:
                params["redirect"] = response.redirect
            self._log(line, response.status, response.response_type, mitre, params)

    def _raw_metadata(self) -> dict:
        metadata = {}
        if self.term_type:
            metadata["terminal_type"] = self.term_type
        return metadata

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
            raw_metadata=self._raw_metadata(),
        ))