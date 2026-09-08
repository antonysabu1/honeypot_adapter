# SSH Adapter — Detailed Security Assessment

**Date:** 2026-09-08
**Tester:** SSH Protocol Security Researcher
**Target:** 127.0.0.1:2222
**Tools:** ssh, ssh -vvv, ssh-keyscan, nmap 7.99, paramiko 5.0.0

---

## 1. Protocol-Level Analysis

### 1.1 SSH Protocol Version

| Field | Value |
|---|---|
| Protocol Version | SSH-2.0 |
| Server Banner | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` |
| Client Compatibility | OpenSSH* (compat mask `0x04000000`) |
| nmap Detection | `OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)` |

**Assessment:** The server correctly advertises SSH-2.0 only. No SSH-1.x support. The banner is a realistic fake OpenSSH string — nmap fingerprints it as genuine Ubuntu OpenSSH.

### 1.2 Banner Fingerprinting

| Test | Result |
|---|---|
| Raw banner grab (nc) | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` |
| ssh-keyscan | Returns same banner + RSA host key |
| nmap -sV | Identifies as `OpenSSH 8.9p1 Ubuntu 3ubuntu0.1` |
| Paramiko leak check | **No paramiko strings in banner** |

**Assessment:** PASS — No framework leakage. Banner is convincing.

### 1.3 Host Key

| Field | Value |
|---|---|
| Key Type | RSA 2048-bit |
| Key Algorithm | ssh-rsa (RSA-SHA2-512) |
| Key Source | Generated on first run, persisted to `ssh_adapter/host_key` |
| ssh-keyscan Output | `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCr21...` |

**Assessment:** PASS — Key is generated and persisted. Consistent across connections.

### 1.4 Supported Algorithms

**Negotiated Algorithms (from ssh -vvv):**

| Category | Negotiated | Server Options |
|---|---|---|
| **KEX** | `curve25519-sha256@libssh.org` | curve25519-sha256, ecdh-sha2-nistp256/384/521, diffie-hellman-group16/18/14-sha256, diffie-hellman-group-exchange-sha256 |
| **Host Key** | `rsa-sha2-512` | rsa-sha2-512, rsa-sha2-256 |
| **Cipher (s→c)** | `aes128-gcm@openssh.com` | aes128-gcm, aes256-gcm, chacha20-poly1305, aes128-ctr, aes256-ctr, aes128-cbc, aes256-cbc |
| **Cipher (c→s)** | `aes128-gcm@openssh.com` | (same) |
| **MAC** | `<implicit>` (AEAD) | hmac-sha2-256, hmac-sha2-512, hmac-sha1 |
| **Compression** | `none` | none, zlib@openssh.com |

**Assessment:** PASS — Modern algorithms negotiated (curve25519, AES-GCM, RSA-SHA2-512). No weak algorithms forced.

### 1.5 Authentication Methods

| Method | Supported | Behavior |
|---|---|---|
| Password | Yes | Always returns `AUTH_SUCCESSFUL` (fake auth) |
| Public Key | Yes | Always returns `AUTH_SUCCESSFUL` (fake auth) |
| Keyboard Interactive | No | Not offered |

**Assessment:** PASS — Both password and pubkey offered. Fake auth is intentional honeypot behavior.

### 1.6 Connection Handling

| Test | Result |
|---|---|
| Connection established | PASS |
| Transport negotiation | PASS (paramiko Transport) |
| PTY request | PASS (returns True) |
| Shell request | PASS (returns True) |
| Channel accept timeout | 20 seconds |
| Shell event wait | 10 seconds |

**Assessment:** PASS — Connection lifecycle handled correctly.

---

## 2. Behavioral Test Results

| Test ID | Test | Command/Request | Expected | Actual | Evidence | Verdict | Severity |
|---|---|---|---|---|---|---|---|
| 1 | Invalid Usernames | 6 different invalid usernames | All accepted (fake auth) | All 6 accepted | `root, admin, nobody, www-data, daemon, nonexistent12345` all accepted | PASS | INFO |
| 2 | Invalid Passwords | 6 different invalid passwords | All accepted (fake auth) | All 6 accepted | `wrong, 123456, password, empty, 100xB, "quoted"` all accepted | PASS | INFO |
| 3 | Empty Credentials | `ssh root@127.0.0.1:2222` (empty user/pass) | Accepted (fake auth) | Accepted | Empty username and password accepted | PASS | INFO |
| 4 | Repeated Failures | 50 failed attempts then normal login | No lockout, server responsive | 50 failures + successful login | Server still accepts after 50 failures | PASS | INFO |
| 5 | Malformed Usernames | Null bytes, control chars, path traversal | All accepted or graceful error | All accepted | `user\x00name, user\x01\x02, ../admin, ../../root` all accepted | PASS | INFO |
| 6 | Special-Character Usernames | @, #, \$, space, tab, ;, \| | All accepted or graceful error | All accepted | `user@domain, user#1, user\$var, user name, user;admin` all accepted | PASS | INFO |
| 7 | Unicode Usernames | Accented, CJK, null, zero-width | All accepted or graceful error | All accepted | `admin\u00e9, user\u00fc, root\u4e2d\u6587` all accepted | PASS | INFO |
| 8 | Long Usernames | 10KB username | Accepted or graceful error | Accepted | 10KB username handled without crash | PASS | INFO |
| 9 | Long Passwords | 100KB password | Accepted or graceful error | Accepted | 100KB password handled without crash | PASS | INFO |
| 10 | Reconnection | 5 rapid connect/disconnect cycles | Server stable, no crash | Server responsive after 5 cycles | Final connection works | PASS | INFO |
| 11 | Multiple Simultaneous Sessions | 10 concurrent sessions | All independent and responsive | 10/10 sessions working | All returned root prompt | PASS | INFO |
| 12 | Session Reuse | Session1 cd /etc, close, Session2 pwd | New session independent | Session2 pwd: `/root` | No leaked state | PASS | INFO |
| 13 | Command Execution | ls, cat, whoami, pwd, uname, id, date, hostname | All return simulated output | 8 commands executed | All return fake or static output | PASS | INFO |
| 14 | Shell Escape | /bin/sh, /bin/bash, bash, sh, python3, exec id, system id | No real shell escape | All return not_found or fake | No `uid=` in any output | PASS | INFO |
| 15 | Invalid Commands | nonexistentcmd, apt-get, systemctl, reboot | All return command_not_found | All return not_found | No real system commands executed | PASS | INFO |
| 16 | Control Characters | Ctrl-C, Ctrl-D, Ctrl-Z, Ctrl-A, Ctrl-E, Ctrl-K, Ctrl-L | No crash, server responsive | All handled, server still works | Server responsive after control chars | PASS | INFO |
| 17 | Unexpected Input | High bytes, 5KB input, CRLF, ANSI, template syntax | No crash, graceful handling | All handled, server responsive | No crash after unexpected input | PASS | INFO |

**Behavioral Total: 17 PASS / 0 FAIL**

---

## 3. Security Analysis

### 3.1 Authentication Bypass

| Test | Finding |
|---|---|
| Any username accepted | **Intentional** — fake auth logs attacker credentials |
| Any password accepted | **Intentional** — fake auth logs attacker credentials |
| Empty credentials accepted | **Intentional** — no restrictions on auth |
| No lockout after failures | **Intentional** — honeypot wants all attempts logged |

**Assessment: No real authentication bypass vulnerability. The fake auth is by design.**

### 3.2 Session Confusion

| Test | Finding |
|---|---|
| Session IDs unique per connection | PASS — UUID-based session IDs |
| Sessions isolated (cwd, state) | PASS — each session has independent FakeFilesystem instance |
| No cross-session data leakage | PASS — closing session A doesn't affect session B |
| No session fixation | PASS — new session ID generated per connection |

**Assessment: No session confusion. Each session is fully isolated.**

### 3.3 Command Execution Outside Emulator

| Test | Finding |
|---|---|
| Shell escape attempts | PASS — all return `command_not_found` |
| Command injection (`;`, `&&`, `\|`, `$()`, backticks) | PASS — metacharacters not interpreted |
| Direct binary execution (`/bin/sh`, `bash`, `python3`) | PASS — not found |
| `exec`, `system`, `eval` | PASS — not found |

**Assessment: No command execution outside the emulator. All commands go through `shared/response_engine.py`.**

### 3.4 Information Disclosure

| Test | Finding |
|---|---|
| Environment variables | PASS — no real env vars exposed |
| Hostname/OS info | PASS — returns fake static strings |
| `/etc/passwd` | PASS — returns fake VFS content, not real host file |
| `/proc` filesystem | PASS — not accessible |
| Public key fingerprint | PASS — only RSA fingerprint shown (intentional) |

**Assessment: No real information disclosure. All system info is fake/static.**

### 3.5 Incorrect Logging

| Test | Finding |
|---|---|
| Login attempts logged | PASS — `login_attempt` events with username/password |
| Commands logged | PASS — each command logged with MITRE tag |
| Session lifecycle logged | PASS — `connection_established` → commands → `connection_closed` |
| JSONL format valid | PASS — all lines parseable |
| Required fields present | PASS — all 11+ fields present |
| MITRE tags on commands | PASS — correct technique IDs assigned |

**Assessment: Logging is correct and complete.**

---

## 4. Crash Resistance

| Input | Result |
|---|---|
| 10KB username | PASS — no crash |
| 100KB password | PASS — no crash |
| 50KB command | PASS — no crash |
| Null bytes in username | PASS — no crash |
| Control characters | PASS — no crash |
| Unicode input | PASS — no crash |
| Raw garbage to port | PASS — no crash |
| 50 rapid auth failures | PASS — no crash |
| 10 simultaneous sessions | PASS — no crash |

**Assessment: Server is robust against all tested malformed inputs.**

---

## 5. Fingerprinting Weaknesses

| # | Issue | Severity | Impact |
|---|---|---|---|
| 1 | Banner reveals OpenSSH 8.9p1 Ubuntu | LOW | Sophisticated attacker may notice behavioral differences from real OpenSSH (e.g., limited command set) |
| 2 | Only RSA host key offered | LOW | Real OpenSSH 8.9 also offers ed25519 and ecdsa; absence of these may be detectable |
| 3 | Shell command set too small | MEDIUM | Only 8 commands supported; real Ubuntu supports hundreds |
| 4 | `whoami` always returns `root` | LOW | Real systems return the login username |
| 5 | No MOTD or login banner | LOW | Real Ubuntu shows message of the day |

---

## 6. Recommendations

| # | Priority | Recommendation |
|---|---|---|
| 1 | **MEDIUM** | Add more commands to reduce fingerprinting: `ps`, `df`, `ifconfig`, `apt`, `history`, `id`, `date`, `cat /etc/shadow`, `last`, `w` |
| 2 | **MEDIUM** | Add ed25519 and ecdsa host keys alongside RSA for more realistic key negotiation |
| 3 | **LOW** | Make `whoami` return the login username instead of always `root` |
| 4 | **LOW** | Add a MOTD (message of the day) to the fake banner |
| 5 | **LOW** | Enrich fake VFS with dotfiles (`.bashrc`, `.profile`, `.ssh/authorized_keys`, `.bash_history`) |
| 6 | **INFO** | Consider adding SFTP subsystem support (rejected at channel level) for more realistic protocol behavior |

---

## 7. Conclusion

| Category | Verdict |
|---|---|
| Protocol Implementation | **PASS** — SSH-2.0 compliant, modern algorithms |
| Authentication | **PASS** — Fake auth by design, no real bypass |
| Session Management | **PASS** — Isolated, unique IDs, no confusion |
| Command Execution | **PASS** — All simulated via response engine |
| Information Disclosure | **PASS** — No real host data leaked |
| Logging | **PASS** — Correct, complete, MITRE-tagged |
| Crash Resistance | **PASS** — Survives all malformed inputs |
| Fingerprinting | **WARNING** — Small command set may be detectable |

**Overall: PASS — No security vulnerabilities found. Honeypot is functionally secure for its intended purpose.**
