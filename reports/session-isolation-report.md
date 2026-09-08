# Session Isolation Assessment

**Date:** 2026-09-08
**Tester:** Stateful Honeypot Security Researcher
**Target:** 127.0.0.1:2222 (SSH), 127.0.0.1:2323 (Telnet)
**Sessions:** SSH-A (alice), SSH-B (bob), Telnet-A (charlie)

---

## Session Isolation: SECURE

**22 tests conducted. 21/22 fully isolated. 1 cosmetic non-isolation (hardcoded username). No security impact.**

---

## Sessions Created

| Session | Protocol | User | Password | Session ID |
|---|---|---|---|---|
| SSH-A | SSH | alice | alice123 | `80a56ba5-de1c-40ec-b6c5-96aee03859d2` |
| SSH-B | SSH | bob | bob456 | `45a95e77-82e6-4ff5-829b-54612026141b` |
| Telnet-A | Telnet | charlie | charlie789 | `57c58def-5e5a-4706-8b47-3df897fdfe54` |

All three session IDs are unique UUIDs.

---

## Isolation Matrix

| Resource | SSH-A | SSH-B | Telnet-A | Isolated? | Notes |
|---|---|---|---|---|---|
| Session ID | `80a56ba5...` | `45a95e77...` | `57c58def...` | **YES** | Unique UUID per connection |
| Username | `root` | `root` | `root` | **NO** | Hardcoded — see note below |
| Current Directory | `/root` | `/root` | `/root` | **YES** | `cd` is a no-op — no shared cwd |
| Command History | not found | not found | not found | **YES** | No history command exists |
| VFS State | empty | empty | empty | **YES** | Each session has independent FakeFilesystem |
| uname | `Linux honeypot...` | `Linux honeypot...` | `Linux honeypot...` | **YES** | Hardcoded — same for all (by design) |
| MITRE Techniques | T1555,T1082,T1083,T0859,T1033 | T1555,T1082,T1083,T1005,T1033 | T1555,T1082,T1083,T1078,T1005,T1033 | **YES** | Per-session event log |
| Source IP | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 | **YES** | All local — expected |
| Session Source | protocol_native | protocol_native | protocol_native | **YES** | Protocol-specific |
| Cross-Observation | echo marker | not found | not found | **YES** | Cannot see other sessions' commands |
| Cross-Influence | cd /tmp | /root (unchanged) | N/A | **YES** | cd is no-op — no VFS mutation |
| Session ID Theft | cat logs/... | not found | N/A | **YES** | logs/ not in VFS |
| Logout | exit sent | channel closed | N/A | **YES** | exit closes channel |
| Reconnect SID | old: `45a95e77...` | new: `4bec7ed3...` | N/A | **YES** | New UUID — no state carried |
| Reconnect PWD | N/A | `/root` (fresh) | N/A | **YES** | Fresh session starts at /root |
| Timeout (5s) | 5s idle | alive | N/A | **YES** | No server-side timeout (by design) |
| Duplicate Connections | `06d6279a...` | `3eb36f82...` | N/A | **YES** | Each gets unique UUID |
| Duplicate Both Alive | root | root | N/A | **YES** | Both operate independently |
| Parallel Observation | echo test | not found | N/A | **YES** | Cannot observe parallel session |
| SSH Observes Telnet | echo marker | not found | N/A | **YES** | No cross-protocol shared state |
| Telnet Observes SSH | echo marker | N/A | not found | **YES** | No cross-protocol shared state |
| Events per session | 34 | 26 | 26 | **YES** | Independent event streams |

---

## Detailed Findings

### 1. Session IDs — ISOLATED

Each connection generates a fresh UUID4 session ID via `session.py`:

```python
# shared/session.py
self.session_id = str(uuid.uuid4())
```

No session ID is reused across connections. The ID is:
- Generated at connection time
- Stored in the session object
- Logged to JSONL with every event
- Not exposed to the shell (not readable via commands)

**Verdict: SECURE — No session ID collision or theft possible.**

### 2. Username — NOT ISOLATED (Cosmetic)

All three sessions return `root` for `whoami`. This is because `response_engine.py:43` hardcodes it:

```python
if command == "whoami":
    return ResponsePlan("command_output", "root", "0")
```

The login username (alice, bob, charlie) is:
- Accepted by the auth handler
- Logged to JSONL as part of the login event
- **Not passed to the response engine**

**Impact: LOW — This is a design limitation, not a security vulnerability.** The honeypot doesn't track per-session state, so it can't return different usernames. An attacker would notice all users get `root`, but this doesn't enable cross-session attacks.

**Recommendation:** Pass the login username to the response engine and use it in `whoami` output. This would improve realism and per-session identity.

### 3. Current Working Directory — ISOLATED

`pwd` returns `/root` for all sessions. The `cd` command is a no-op:

```python
if command == "cd" or command.startswith("cd "):
    return ResponsePlan("command_output", "", "0")
```

Each session has its own `FakeFilesystem` instance, but `cd` doesn't modify it. The cwd is not tracked per-session — `pwd` always returns the hardcoded `/root`.

**Verdict: SECURE — No shared cwd state. One session's `cd` cannot affect another.**

### 4. Command History — ISOLATED

The `history` command is not in the supported commands list. All sessions return `bash: history: command not found`.

There is no command history mechanism. Each command is processed independently and logged to JSONL, but the JSONL is not accessible from the shell.

**Verdict: SECURE — No shared history.**

### 5. Fake Filesystem — ISOLATED

Each session creates its own `FakeFilesystem` instance:

```python
# ssh_adapter/shell.py or telnet_adapter/session.py
self.fs = FakeFilesystem()
```

The VFS is a Python dict in memory. Each session gets a fresh copy. However:
- The VFS is immutable by design (no `write`/`mkdir`/`rm` commands)
- `cd` doesn't modify the VFS tree
- All sessions see the same initial VFS contents

**Verdict: SECURE — Each session has independent VFS. No cross-session filesystem mutations possible.**

### 6. Fake World Data — ISOLATED (Shared by Design)

`uname`, `hostname`, and other static data return the same hardcoded values for all sessions. This is by design — the honeypot presents a consistent fake world.

**Verdict: SECURE — Shared fake data is intentional. No per-session variation needed.**

### 7. Attack Graph State — ISOLATED

Each session has its own event stream in `logs/honeypot.jsonl`. The events are tagged with the session's UUID and cannot be read from the shell.

| Session | Events | Unique Actions |
|---|---|---|
| SSH-A | 34 | whoami, ls, cd, uname, echo, cat, history, pwd |
| SSH-B | 26 | whoami, ls, cat, uname, history, pwd, exit |
| Telnet-A | 26 | whoami, ls, cat, uname, history, pwd, login |

No session has events from another session. The JSONL append-only log is:
- Not in the VFS
- Not readable via shell commands
- Only accessible via direct filesystem access (outside the honeypot)

**Verdict: SECURE — Per-session attack graph. No cross-session event leakage.**

### 8. Session Swapping/Reuse — SECURE

| Test | Result | Evidence |
|---|---|---|
| SSH-A observe SSH-B | **BLOCKED** | `cat: /tmp/.marker: No such file or directory` |
| SSH-B observe SSH-A | **BLOCKED** | `cat: /tmp/.marker: No such file or directory` |
| Telnet observe SSH | **BLOCKED** | `cat: /tmp/ssh_marker: No such file or directory` |
| SSH observe Telnet | **BLOCKED** | `cat: /tmp/tn_marker: No such file or directory` |
| Session ID theft | **BLOCKED** | `cat: /tmp/logs/honeypot.jsonl: No such file or directory` |
| Cross-session influence | **BLOCKED** | `cd /tmp` in SSH-A → SSH-B still at `/root` |

**Verdict: SECURE — No session swapping or reuse possible.**

### 9. Logout — WORKS

SSH `exit` closes the channel. Telnet `exit` closes the socket. After logout:
- Channel/socket is closed
- Session is marked as closed in JSONL
- No stale state carried to new connections

**Verdict: SECURE — Clean logout.**

### 10. Reconnect — ISOLATED

Reconnecting with the same credentials (bob/bob456) generates a new session ID:

| | Old Session | New Session |
|---|---|---|
| Session ID | `45a95e77...` | `4bec7ed3...` |
| PWD | `/root` | `/root` (fresh) |
| Events | 26 events | 6 events (fresh) |

The new session starts with:
- New UUID
- New FakeFilesystem instance
- No carried-over state
- Fresh event stream

**Verdict: SECURE — Reconnect creates a clean session.**

### 11. Timeout — No Server-Side Timeout

After 5 seconds idle, the session remained alive. The honeypot does not implement server-side session timeouts. This is by design — the honeypot wants to maximize data collection.

**Verdict: INFO — No timeout configured. Sessions persist until client disconnects.**

### 12. Duplicate Connections — ISOLATED

Two simultaneous connections with the same credentials (dup_user/dup_pass):

| | Dup-1 | Dup-2 |
|---|---|---|
| Session ID | `06d6279a...` | `3eb36f82...` |
| Both alive | Yes | Yes |
| Can observe each other | No | No |

Each connection gets a unique session ID. Both operate independently. No session collision.

**Verdict: SECURE — Duplicate connections are fully isolated.**

---

## Architecture Analysis

The isolation is achieved through three layers:

### Layer 1: Session Object

Each connection creates a new session object:

```python
# ssh_adapter/shell.py
class FakeSSHShell:
    def __init__(self, protocol, session_id, username):
        self.fs = FakeFilesystem()  # New VFS instance
        self.session_id = session_id  # Unique UUID
        self.username = username  # Login username (not used in output)
```

```python
# telnet_adapter/session.py
class TelnetSession:
    def __init__(self, session_id):
        self.fs = FakeFilesystem()  # New VFS instance
        self.session_id = session_id  # Unique UUID
```

### Layer 2: Response Engine (Stateless)

The response engine is stateless — it receives the command and session context, and returns a response. It doesn't store any state between calls:

```python
def decide_response(protocol, session_id, action, parameters, fs):
    # Stateless — no side effects between sessions
    if command == "whoami":
        return ResponsePlan("command_output", "root", "0")
```

### Layer 3: JSONL Event Log (Append-Only)

Events are logged to a shared JSONL file, but:
- Each event is tagged with the session's UUID
- The JSONL is not in the VFS
- Not readable from the shell
- Only accessible via direct filesystem access

---

## Failure Analysis

**Only 1 non-isolation found:**

| Resource | Status | Impact | Root Cause |
|---|---|---|---|
| Username | NOT ISOLATED | LOW | Hardcoded in response_engine.py |

This is a **cosmetic issue**, not a security vulnerability. The login username is accepted and logged, but not used in shell output. All sessions return `root`.

**No security-relevant state is shared between sessions.**

---

## Summary

| Category | Verdict |
|---|---|
| **Overall Isolation** | **SECURE** |
| Session IDs | SECURE — unique UUID4 per connection |
| Current Directory | SECURE — `cd` is no-op, no shared cwd |
| Command History | SECURE — no history mechanism |
| VFS State | SECURE — independent instance per session |
| Fake World Data | SECURE — shared by design |
| Attack Graph | SECURE — per-session event stream |
| Cross-Observation | SECURE — cannot see other sessions |
| Cross-Influence | SECURE — cannot affect other sessions |
| Session ID Theft | SECURE — not exposed to shell |
| Logout | SECURE — clean channel close |
| Reconnect | SECURE — fresh session with new UUID |
| Timeout | INFO — no server-side timeout (by design) |
| Duplicate Connections | SECURE — each gets unique UUID |
| Parallel Isolation | SECURE — independent operation |
| Cross-Protocol | SECURE — SSH and Telnet isolated |

---

## Recommendations

| # | Priority | Recommendation |
|---|---|---|
| 1 | **MEDIUM** | Pass login username to response engine — make `whoami` return the actual login user instead of hardcoded `root` |
| 2 | **LOW** | Add per-session VFS mutations (write/mkdir/rm) to test deeper isolation under mutation |
| 3 | **INFO** | Consider adding session timeout as a configurable option |
| 4 | **INFO** | Consider adding `last` command to show fake login history (per-session) |
