# Honeypot Adapter — Basic Functionality Report

**Date:** 2026-09-08
**Engineer:** Senior Network-Security QA
**Scope:** Localhost-only testing of SSH and Telnet honeypot adapters
**Project:** `/home/antony/adapter/new/`

---

## 1. Project Architecture Summary

| Component | Details |
|---|---|
| **SSH Adapter** | `ssh_adapter/server.py` + `ssh_adapter/shell.py` |
| **Telnet Adapter** | `telnet_adapter/server.py` + `telnet_adapter/session.py` |
| **Shared Modules** | `shared/logger.py`, `shared/session.py`, `shared/filesystem.py`, `shared/response_engine.py`, `shared/mitre.py` |
| **Entry Point** | `python3 main.py` |
| **SSH Port** | 2222 (TCP, paramiko, `socketserver.ThreadingTCPServer`) |
| **Telnet Port** | 2323 (TCP, asyncio Protocol) |
| **Log Output** | `logs/honeypot.jsonl` (one JSON object per line) |

### Startup Mechanism
- `main.py` starts SSH in a daemon thread, then runs Telnet via `asyncio.run()` on the main thread.
- Both servers are fully independent; killing one does not affect the other.

### Authentication Mechanism
- **SSH:** paramiko `check_auth_password` and `check_auth_publickey` — **always returns `AUTH_SUCCESSFUL`** regardless of input. Fake auth.
- **Telnet:** state machine (`login` → `password` → `shell`) — **always accepts any username/password**. Fake auth.

### Session-Management Mechanism
- `shared/session.py` — `create_session_id()` generates a UUID; `SessionTracker.start_session()` / `end_session()` tracks per-protocol sessions in memory.
- Each connection (SSH and Telnet) gets a unique `session_id`. No cross-protocol ID overlap verified.

### Logging Mechanism
- `shared/logger.py` — `log_event()` validates required keys, appends one JSON line per event to `logs/honeypot.jsonl`, prints a summary line to stdout.
- **Required schema:** `event_id, timestamp, protocol, source_ip, session_id, action, parameters, raw_metadata, session_source, response_status, response_type`
- **MITRE fields (extended):** `mitre_attack_id, mitre_technique_name, mitre_tactic, mitre_attack_id_secondary, mitre_technique_name_secondary, mitre_confidence` — present on command events.

### Fake Shell / Command Implementation
- `ssh_adapter/shell.py` — `FakeSSHShell.run()` handles byte-level input processing (Enter, backspace, Ctrl+C, echo). `handle_command()` routes through `shared/response_engine.decide_response()`.
- `telnet_adapter/session.py` — `TelnetSession.process_line()` routes commands through the same `decide_response()`.
- **Supported commands:** `ls`, `cat`, `pwd`, `whoami`, `uname`, `cd`, `exit`. Unknown → `command not found` (status 127).

---

## 2. Startup Result

| Item | Result |
|---|---|
| `python3 main.py` starts both servers | **PASS** |
| SSH listening on 2222 | **PASS** |
| Telnet listening on 2323 | **PASS** |
| No errors or warnings on startup | **PASS** |

---

## 3. SSH Test Results

| Test | Verdict | Details |
|---|---|---|
| **TCP Connectivity** | **PASS** | TCP connection to port 2222 established within timeout. |
| **SSH Handshake** | **PASS** | Full paramiko handshake completes successfully. |
| **Banner** | **PASS** | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` received. Realistic fake banner. |
| **Auth Prompt (password)** | **PASS** | Any credentials accepted (fake auth — correct honeypot behavior). |
| **Valid Synthetic Credentials** | **PASS** | `admin/admin` accepted. No rejection. |
| **Invalid Credentials** | **PASS** | `root/definitelywrong` accepted (expected for honeypot). |
| **Shell/Prompt Behavior** | **PASS** | Welcome banner (`Welcome to Ubuntu 22.04.3 LTS`) + prompt (`root@honeypot:~#`) received. |
| **Command: `ls`** | **PASS** | Returns `README`, `flag.txt` (fake filesystem contents). |
| **Command: `whoami`** | **PASS** | Returns `root`. |
| **Command: `exit`** | **PASS** | Exit accepted, channel cleanly closed. |
| **Reconnect** | **PASS** | Second connection after first session exit works — new session, new prompt. |

**SSH Total: 11 PASS / 0 FAIL**

---

## 4. Telnet Test Results

| Test | Verdict | Details |
|---|---|---|
| **TCP Connectivity** | **PASS** | TCP connection to port 2323 established within timeout. |
| **Telnet Negotiation (IAC)** | **PASS** | IAC DO SUPPRESS-GO-AHEAD handled without crash. Server filters IAC bytes correctly. |
| **Banner + Login Prompt** | **PASS** | Welcome banner + `login: ` prompt received. |
| **Username Prompt** | **PASS** | `login: ` prompt appears after connection. |
| **Password Prompt** | **PASS** | `Password: ` prompt received after sending username. |
| **Invalid Credentials** | **PASS** | `baduser/badpass` accepted — shell prompt returned (expected honeypot behavior). |
| **Valid Synthetic Credentials** | **PASS** | `admin/secret` accepted — shell prompt returned. |
| **Command Prompt** | **PASS** | `root@honeypot:~# ` prompt displayed after login. |
| **Command: `ls`** | **PASS** | Returns `README`, `flag.txt` (fake filesystem). |
| **Command: `whoami`** | **PASS** | Returns `root`. |
| **Logout (`exit`)** | **PASS** | `exit` command accepted, connection closed. |
| **Reconnect** | **PASS** | Second connection after first session exit works — new session established. |

**Telnet Total: 12 PASS / 0 FAIL**

---

## 5. Logging Behavior

| Test | Verdict | Details |
|---|---|---|
| **JSONL format valid** | **PASS** | Every line in `logs/honeypot.jsonl` is valid JSON (no parse errors). |
| **Required fields present** | **PASS** | All 11 required keys present in every event. No missing fields. |
| **Protocol field correct** | **PASS** | SSH events have `protocol: "ssh"`, Telnet events have `protocol: "telnet"`. |
| **Session ID uniqueness** | **PASS** | 25 unique session IDs observed across QA test events. No duplicates. |
| **Cross-protocol session ID isolation** | **PASS** | SSH session IDs and Telnet session IDs are disjoint (no overlap). |
| **MITRE fields on command events** | **PASS** | `mitre_attack_id`, `mitre_technique_name`, `mitre_confidence` present on command events. |
| **MITRE field values** | **PASS** | Verified: `ls` → T1083 (File and Directory Discovery), `whoami` → T1033 (System Owner/User Discovery). |
| **Connection lifecycle logged** | **PASS** | `connection_established` → `login_attempt` → commands → `connection_closed` sequence observed. |
| **Event count consistency** | **PASS** | 80 QA events logged: 18 SSH + 62 Telnet. Correct per-protocol breakdown. |

---

## 6. Failures & Issues

| # | Severity | Issue | Status |
|---|---|---|---|
| 1 | — | **No failures observed.** All tests passed. | — |

---

## 7. Recommendations

| # | Priority | Recommendation |
|---|---|---|
| 1 | **LOW** | `exit` maps to T0859 (Valid Accounts) with `low` confidence — technically accurate but semantically odd. Consider adding `exit` → a `session_end` or `T1070` (Indicator Removal) tag since the attacker is cleaning up. |
| 2 | **MEDIUM** | The fake filesystem returns only `README` and `flag.txt` for `ls /root`. Consider populating `/root/.ssh/`, `/var/log/`, `/tmp/` to make `ls -la` output more convincing. |
| 3 | **MEDIUM** | `whoami` always returns `root`. Consider accepting the login username as parameter for multi-user realism (e.g. if attacker logs in as `admin`, `whoami` returns `admin`). |
| 4 | **LOW** | IAC handling silently drops bytes. For advanced telnet clients that send IAC sequences (NAWS, TTYPE, etc.), consider sending IAC WILL/WONT responses to avoid client hangs on strict implementations. |
| 5 | **LOW** | Add a `history` or `last` command to the response engine — attackers frequently check these to understand system state. |
| 6 | **INFO** | `scripts/technique_summary.py` works well as a CLI. Consider adding a `--json` output mode for programmatic consumption. |

---

## 8. Summary

| Category | Verdict |
|---|---|
| **Startup** | **PASS** — Both servers start cleanly on ports 2222/2323 |
| **SSH** | **PASS** — 11/11 tests passed |
| **Telnet** | **PASS** — 12/12 tests passed |
| **Logging** | **PASS** — JSONL format, required fields, MITRE tags, session isolation all correct |
| **Overall** | **PASS** — Honeypot adapters are functional and ready for use |

**Total: 23 PASS / 0 FAIL / 0 WARNING**
