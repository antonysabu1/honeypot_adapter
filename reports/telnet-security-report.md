# Telnet Adapter — Detailed Security Assessment

**Date:** 2026-09-08
**Tester:** Telnet Protocol Security Researcher
**Target:** 127.0.0.1:2323
**Tools:** Raw TCP sockets (Python socket module), paramiko (for SSH cross-check)

---

## 1. Protocol-Level Analysis

### 1.1 TCP Connection

| Field | Value |
|---|---|
| Transport | TCP over IPv4 |
| Bind Address | 0.0.0.0:2323 |
| Protocol | asyncio Protocol (Python) |
| Backlog | 100 |

**Assessment:** PASS — Connection establishes correctly.

### 1.2 Telnet Negotiation

| Test | Input | Response | Verdict |
|---|---|---|---|
| IAC DO SUPPRESS-GO-AHEAD | `\xff\xfd\x03` | Handled (IAC filtered) | PASS |
| IAC WILL SUPPRESS-GO-AHEAD | `\xff\xfb\x03` | Handled | PASS |
| IAC WONT SUPPRESS-GO-AHEAD | `\xff\xfc\x03` | Handled | PASS |
| IAC DONT SUPPRESS-GO-AHEAD | `\xff\xfe\x03` | Handled | PASS |
| IAC DO TERMINAL-TYPE | `\xff\xfd\x18` | Handled | PASS |
| IAC SB TERMINAL-TYPE SEND | `\xff\xfa\x18\x01\xff\xf0` | Handled | PASS |
| IAC NOP | `\xff\xf1` | Handled | PASS |
| IAC GA | `\xff\xf9` | Handled | PASS |

**Assessment:** PASS — All IAC sequences filtered silently. No WILL/WONT responses sent (server does not negotiate options). This is safe but minimal.

### 1.3 IAC Handling Mechanism

The server filters IAC bytes in `telnet_adapter/session.py:25-42`:

```python
if byte == 255:  # IAC — skip 2 more bytes (3-byte sequence)
    i += 3
    continue
```

**Limitation:** Only handles 3-byte IAC sequences. IAC SB (subnegotiation) sequences are longer and may cause parsing issues if the skip doesn't align with IAC SE. In practice, the current implementation silently drops bytes until the next newline, which is safe but imprecise.

**Assessment:** PASS — Safe handling, but could be more robust for strict telnet clients.

### 1.4 Banner

| Field | Value |
|---|---|
| Banner | `Welcome to Ubuntu 22.04 LTS` |
| Login Prompt | `login: ` |
| Password Prompt | `Password: ` |
| Shell Prompt | `root@honeypot:~# ` |

**Assessment:** PASS — Realistic fake banner. No framework leakage.

### 1.5 Echo Behavior

| Test | Result |
|---|---|
| Single character echo | Characters echoed back during login |
| Password echo | Password not echoed (server consumes input) |

**Assessment:** PASS — Standard telnet echo behavior.

### 1.6 Line Endings

| Input | Result |
|---|---|
| CR (`\r`) | Command processed |
| LF (`\n`) | Command processed |
| CRLF (`\r\n`) | Command processed |

**Assessment:** PASS — All three line ending styles handled correctly.

---

## 2. Behavioral Test Results

| Test ID | Test | Command/Request | Expected | Actual | Evidence | Verdict | Severity |
|---|---|---|---|---|---|---|---|
| 11 | Empty Input | Bare CRLF at shell prompt | Prompt reprinted, no crash | Prompt reprinted | `root@honeypot:~#` | PASS | INFO |
| 12 | Long Input | 50KB command input | No crash, graceful handling | Handled, returned not_found | No crash | PASS | INFO |
| 13 | Special Characters | `ls $HOME`, `cat /etc/passwd; echo PWNED`, `echo "hello"`, `ls \| wc -l`, `echo $((1+1))`, `ls > /tmp/x` | No real shell interpretation | `cat /etc/passwd; echo PWNED` — semicolon treated as filename. `echo PWNED` is a separate simulated command returning its argument. No shell metacharacters interpreted | `cat: /etc/passwd;: No such file or directory` | PASS | INFO |
| 14 | Unicode | Zero-width, null, combining, RTL, unicode symbols | No crash, graceful handling | All handled | No crash | PASS | INFO |
| 15 | Control Characters | Ctrl-C, Ctrl-D, Ctrl-Z, Ctrl-A, Ctrl-E, Ctrl-K, Ctrl-L | No crash, server responsive | Server still works | `whoami` returns root after control chars | PASS | INFO |
| 16 | Malformed Negotiation | Incomplete IAC, double IAC, random IAC bytes | No crash, server survives | Server survived | No crash | PASS | INFO |
| 17 | Unexpected Negotiation | SB without END, NOP, GA | No crash, server survives | Server survived | No crash | PASS | INFO |
| 18 | Invalid Commands | nonexistentcmd, xyz123, apt-get, systemctl, reboot | All return command_not_found | All return not_found | No real commands executed | PASS | INFO |
| 19 | Repeated Authentication | 10 rapid auth cycles | All accepted, server stable | All 10 accepted | No lockout, no crash | PASS | INFO |
| 20 | Reconnects | 5 rapid connect/disconnect cycles | Server stable, new session works | Server responsive | Final login prompt received | PASS | INFO |
| 21 | Session Isolation | Session1 cd /etc, close, Session2 pwd | New session independent | Session2 pwd: `/root` | No leaked state | PASS | INFO |
| 22 | Command Execution | ls, cat, whoami, pwd, uname, id, date, hostname | All return simulated output | 8 commands executed | All return fake or static output | PASS | INFO |
| 23 | Shell Escape | /bin/sh, /bin/bash, bash, sh, python3, exec id, system id | No real shell escape | All return not_found or fake | No `uid=` in any output | PASS | INFO |
| 24 | Path Traversal | ../../../etc/passwd, ../../, etc | Fake FS only, no real access | All return fake VFS content or not_found | No real host file accessed | PASS | INFO |
| 25 | Connection Termination | Clean exit + abrupt close | Server survives both | Server responsive after both | Both handled gracefully | PASS | INFO |
| 26 | Logging Verification | Check JSONL for telnet events | Events present with correct fields | 48+ telnet events, multiple sessions, MITRE tags present | Actions: connection_established, login_attempt, commands, connection_closed | PASS | INFO |

**Behavioral Total: 16 PASS / 0 FAIL**

---

## 3. Security Analysis

### 3.1 Authentication Bypass

| Test | Finding |
|---|---|
| Any username accepted | **Intentional** — fake auth logs attacker credentials |
| Any password accepted | **Intentional** — fake auth logs attacker credentials |
| No lockout after failures | **Intentional** — honeypot wants all attempts logged |

**Assessment: No real authentication bypass vulnerability. The fake auth is by design.**

### 3.2 Session Confusion

| Test | Finding |
|---|---|
| Session IDs unique per connection | PASS — UUID-based session IDs |
| Sessions isolated (cwd, state) | PASS — each session has independent FakeFilesystem instance |
| No cross-session data leakage | PASS — closing session A doesn't affect session B |

**Assessment: No session confusion. Each session is fully isolated.**

### 3.3 Command Parser Problems

| Test | Finding |
|---|---|
| Shell metacharacters (`;`, `&&`, `\|`, `$()`) | Not interpreted — safe |
| `echo` command | Simulated — returns its argument (not real execution) |
| Unknown commands | Return `command_not_found` |
| Empty input | Prompt reprinted |

**Assessment: No command parser vulnerabilities. All commands go through `shared/response_engine.py`.**

### 3.4 Logging Failures

| Test | Finding |
|---|---|
| Events written to JSONL | PASS — correct format |
| Required fields present | PASS — all 11+ fields present |
| MITRE tags on commands | PASS — correct technique IDs |
| Session lifecycle logged | PASS — established → commands → closed |

**Assessment: Logging is correct and complete.**

### 3.5 Incorrect Attack Classification

| Test | Finding |
|---|---|
| MITRE tags correct | `ls` → T1083, `whoami` → T1033, `cat` → T1005, `wget` → T1105 |
| Login tagged | T1078 (Valid Accounts) |
| Unknown commands | T0859 (Valid Accounts, low confidence) |

**Assessment: Attack classification is correct and useful for SIEM correlation.**

---

## 4. Crash Resistance

| Input | Result |
|---|---|
| 50KB command | PASS — no crash |
| Null bytes in command | PASS — no crash |
| Control characters | PASS — no crash |
| Unicode input | PASS — no crash |
| Malformed IAC sequences | PASS — no crash |
| Incomplete IAC (IAC only) | PASS — no crash |
| Multiple IAC bytes | PASS — no crash |
| 10 rapid auth cycles | PASS — no crash |
| Abrupt connection close | PASS — no crash |

**Assessment: Server is robust against all tested malformed inputs.**

---

## 5. Fingerprinting Weaknesses

| # | Issue | Severity | Impact |
|---|---|---|---|
| 1 | No IAC WILL/WONT responses | LOW | Strict telnet clients may hang waiting for option negotiation |
| 2 | IAC skip is always 3 bytes | LOW | Subnegotiation (IAC SB) sequences longer than 3 bytes may cause byte misalignment |
| 3 | Shell command set too small | MEDIUM | Only 8 commands supported; real Ubuntu supports hundreds |
| 4 | `whoami` always returns `root` | LOW | Real systems return the login username |
| 5 | No MOTD or login banner | LOW | Real Ubuntu shows message of the day |

---

## 6. Recommendations

| # | Priority | Recommendation |
|---|---|---|
| 1 | **MEDIUM** | Add more commands to reduce fingerprinting: `ps`, `df`, `ifconfig`, `apt`, `history`, `id`, `date`, `cat /etc/shadow`, `last`, `w` |
| 2 | **MEDIUM** | Improve IAC handling to support subnegotiation (IAC SB ... IAC SE) properly — parse until IAC SE instead of fixed 3-byte skip |
| 3 | **LOW** | Add IAC WILL responses for ECHO and SUPPRESS-GO-AHEAD to satisfy strict telnet clients |
| 4 | **LOW** | Make `whoami` return the login username instead of always `root` |
| 5 | **LOW** | Add a MOTD (message of the day) after login |
| 6 | **INFO** | Consider adding a `--json` output mode to `scripts/technique_summary.py` for programmatic consumption |

---

## 7. Conclusion

| Category | Verdict |
|---|---|
| TCP Connection | **PASS** |
| Telnet Negotiation | **PASS** — IAC handled safely |
| IAC Handling | **PASS** — filtered silently (3-byte skip) |
| Banner | **PASS** — no framework leakage |
| Echo Behavior | **PASS** |
| Line Endings | **PASS** — CR, LF, CRLF all work |
| Username Handling | **PASS** |
| Password Handling | **PASS** |
| Command Handling | **PASS** — all simulated |
| Session Isolation | **PASS** |
| Command Execution | **PASS** — all simulated |
| Shell Escape | **PASS** — all blocked |
| Path Traversal | **PASS** — fake FS only |
| Connection Termination | **PASS** — clean + abrupt both handled |
| Logging | **PASS** — correct, complete, MITRE-tagged |
| Crash Resistance | **PASS** — survives all malformed inputs |
| Attack Classification | **PASS** — correct MITRE tags |
| Fingerprinting | **WARNING** — small command set may be detectable |

**Overall: PASS — No security vulnerabilities found. Honeypot is functionally secure for its intended purpose.**
