# Honeypot Shell Escape Assessment

**Date:** 2026-09-08
**Tester:** Honeypot Escape Researcher
**Target:** 127.0.0.1:2222 (SSH), 127.0.0.1:2323 (Telnet)
**Objective:** Determine whether attacker-controlled input can reach the real OS command interpreter

---

## Shell Containment: SECURE

**Verdict: No shell escape found. All outputs are simulated or served from a hardcoded virtual filesystem (VFS). No real host command execution occurred.**

---

## Real Host Reference

To detect leaks, the real host outputs were captured first:

| Command | Real Host Output |
|---|---|
| `whoami` | `antony` |
| `id` | `uid=1000(antony) gid=1000(antony) groups=1000(antony),4(adm),...` |
| `pwd` | `/home/antony/adapter` |
| `hostname` | `kali` |
| `uname -a` | `Linux kali 7.0.12+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.0.12-2kali1` |
| `ls /` | `bin boot dev etc home ...` (22 entries) |
| `id -u` | `1000` |
| `id -un` | `antony` |

---

## Architecture Analysis

The honeypot shell is NOT a real shell. The architecture is:

```
Attacker input
    ↓
Protocol handler (paramiko / asyncio)
    ↓
Command parser (shell.py / session.py)
    ↓
shared/response_engine.py — hardcoded command dispatch
    ↓
shared/filesystem.py — hardcoded VFS (dict in memory)
    ↓
Response sent back to attacker
```

**No subprocess, no os.system, no os.exec, no shell=True, no exec(), no eval().**

The `response_engine.py` supports exactly 7 commands:

| Command | Handler | Output Source |
|---|---|---|
| `ls [path]` | `fs.ls(path)` | VFS dict lookup |
| `cat [path]` | `fs.cat(path)` | VFS dict lookup |
| `pwd` | hardcoded | Returns `/root` |
| `whoami` | hardcoded | Returns `root` |
| `uname [-a]` | hardcoded | Returns fake Ubuntu string |
| `cd [path] | hardcoded | Returns empty string |
| `exit` | hardcoded | Ends session |

**Everything else** → `bash: {command}: command not found` (exit code 127)

---

## VFS Contents (Hardcoded)

The VFS is a Python dict, NOT a real filesystem:

```python
{
    "etc": {
        "passwd": "root:x:0:0:root:/root:/bin/bash\n"
                   "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                   "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
        "shadow": "root:*:19840:0:99999:7:::\n"
                   "daemon:*:19840:0:99999:7:::\n",
        "hosts": "127.0.0.1 localhost\n127.0.1.1 honeypot\n",
    },
    "home": {"admin": {"notes.txt": "password123\n"}, "user": {}},
    "root": {"flag.txt": "flag{you_got_pwned}\n", "README": "Do not delete this file.\n"},
    "var": {"www": {"html": {"index.html": "..."}}},
    ...
}
```

**Key differences from real host:**

| File | VFS Content | Real Host Content |
|---|---|---|
| `/etc/passwd` | 4 entries (root, daemon, bin, sys) | 30+ entries including `antony:x:1000:1000:...` |
| `/etc/shadow` | 2 entries (root, daemon) with `*` (locked) | Real password hashes |
| `/etc/hosts` | `127.0.0.1 localhost` | Full real hosts file |
| `/root/` | `flag.txt`, `README` | Real root home dir |
| `/home/` | `admin/`, `user/` | Real home dirs |

---

## Test Results

### Section 1: Basic Commands

| Protocol | Command | Output | Classification | Evidence |
|---|---|---|---|---|
| SSH | `whoami` | `root` | **FAKE/SIMULATED** | Hardcoded in response_engine.py:43 |
| SSH | `id` | `bash: id: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `pwd` | `/root` | **FAKE/SIMULATED** | Hardcoded in response_engine.py:40 |
| SSH | `hostname` | `bash: hostname: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `uname` | `Linux honeypot 5.15.0-105-generic...` | **FAKE/SIMULATED** | Hardcoded in response_engine.py:48 |
| SSH | `uname -a` | `Linux honeypot 5.15.0-105-generic...` | **FAKE/SIMULATED** | Same hardcoded string |
| SSH | `echo test` | `bash: echo test: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| Telnet | `whoami` | `root` | **FAKE/SIMULATED** | Same response_engine |
| Telnet | `id` | `bash: id: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| Telnet | `pwd` | `/root` | **FAKE/SIMULATED** | Same response_engine |

### Section 2: Shell Syntax (Parser Edge Cases)

| Protocol | Command | Output | Classification | Evidence |
|---|---|---|---|---|
| SSH | `echo test \| cat` | `bash: echo test \| cat: command not found` | **FAKE/SIMULATED** | Pipes not parsed — entire string treated as command name |
| SSH | `echo test; echo hack` | `bash: echo test; echo hack: command not found` | **FAKE/SIMULATED** | Semicolons not parsed — entire string treated as command name |
| SSH | `echo "hello"` | `bash: echo "hello": command not found` | **FAKE/SIMULATED** | Quotes not parsed |
| SSH | `echo $(whoami)` | `bash: echo $(whoami): command not found` | **FAKE/SIMULATED** | Command substitution not parsed |
| SSH | `ls > /dev/null` | (empty) | **FAKE/SIMULATED** | Redirect operator `>` not parsed — `ls` executed, output empty |
| SSH | `ls /etc/p*` | (empty) | **FAKE/SIMULATED** | Glob `*` not parsed — `ls` executed with literal path `/etc/p*` |
| SSH | `cat /etc/passwd` | `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...` | **FAKE/SIMULATED** | VFS content (4 entries). Real host has 30+ entries with `antony` |
| SSH | `cat /proc/1/cmdline` | `cat: /proc/1/cmdline: No such file or directory` | **FAKE/SIMULATED** | `/proc` not in VFS |
| SSH | `cat /proc/self/environ` | `cat: /proc/self/environ: No such file or directory` | **FAKE/SIMULATED** | `/proc` not in VFS |
| SSH | `cat /proc/version` | `cat: /proc/version: No such file or directory` | **FAKE/SIMULATED** | `/proc` not in VFS |
| SSH | `id; whoami; pwd` | `bash: id; whoami; pwd: command not found` | **FAKE/SIMULATED** | Chained commands not parsed |
| SSH | `whoami && echo done` | `bash: whoami && echo done: command not found` | **FAKE/SIMULATED** | `&&` not parsed |
| SSH | `whoami \|\| echo fail` | `bash: whoami \|\| echo fail: command not found` | **FAKE/SIMULATED** | `\|\|` not parsed |
| SSH | `(echo subshell)` | `bash: (echo subshell): command not found` | **FAKE/SIMULATED** | Subshell not parsed |
| SSH | `env` | `bash: env: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `eval echo test` | `bash: eval echo test: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `exec echo test` | `bash: exec echo test: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `date` | `bash: date: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `ps` | `bash: ps: command not found` | **FAKE/SIMULATED** | Not in supported commands |
| SSH | `cat /etc/passwd \| grep root` | `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...` | **FAKE/SIMULATED** | Pipe not parsed — `cat` ignores everything after `\|` |
| SSH | `ls \| wc -l` | (empty) | **FAKE/SIMULATED** | Pipe not parsed — `ls` executed |
| Telnet | `echo test \| cat` | `bash: echo test \| cat: command not found` | **FAKE/SIMULATED** | Same behavior as SSH |
| Telnet | `echo test; echo hack` | `bash: echo test; echo hack: command not found` | **FAKE/SIMULATED** | Same behavior as SSH |
| Telnet | `cat /etc/passwd` | `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...` | **FAKE/SIMULATED** | Same VFS content |

### Section 3: Variable Expansion

| Protocol | Command | Output | Classification | Evidence |
|---|---|---|---|---|
| SSH | `echo $PATH` | `bash: echo $PATH: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| SSH | `echo $HOME` | `bash: echo $HOME: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| SSH | `echo $USER` | `bash: echo $USER: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| SSH | `echo $SHELL` | `bash: echo $SHELL: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| SSH | `echo $$` | `bash: echo $$: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| SSH | `echo $?` | `bash: echo $?: command not found` | **FAKE/SIMULATED** | `echo` not supported |
| Telnet | `echo $PATH` | `bash: echo $PATH: command not found` | **FAKE/SIMULATED** | Same |

### Section 4: Dangerous Paths

| Protocol | Command | Output | Classification | Evidence |
|---|---|---|---|---|
| SSH | `cat /etc/shadow` | `root:*:19840:0:99999:7:::\ndaemon:*:19840:0:99999:7:::` | **FAKE/SIMULATED** | VFS content (2 entries, `*` locked). Real shadow has real hashes |
| SSH | `cat /etc/passwd` | `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...` | **FAKE/SIMULATED** | VFS content (4 entries). Real has 30+ entries with `antony` |
| SSH | `cat /root/.bash_history` | `cat: /root/.bash_history: No such file or directory` | **FAKE/SIMULATED** | Not in VFS |
| SSH | `cat /home/antony/.ssh/id_rsa` | `cat: /home/antony/.ssh/id_rsa: No such file or directory` | **FAKE/SIMULATED** | Path from attacker input echoed in error. `/home/antony` NOT in VFS |
| SSH | `cat /etc/ssh/sshd_config` | `cat: /etc/ssh/sshd_config: No such file or directory` | **FAKE/SIMULATED** | Not in VFS |
| SSH | `ls /root` | `README\nflag.txt` | **FAKE/SIMULATED** | VFS content matches exactly |
| SSH | `ls /home` | `admin\nuser` | **FAKE/SIMULATED** | VFS content matches exactly |
| SSH | `ls /etc` | `hosts\npasswd\nshadow` | **FAKE/SIMULATED** | VFS content matches exactly (3 entries vs real ~30) |
| Telnet | `cat /etc/passwd` | `root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...` | **FAKE/SIMULATED** | Same VFS content |
| Telnet | `cat /etc/shadow` | `root:*:19840:0:99999:7:::\ndaemon:*:19840:0:99999:7:::` | **FAKE/SIMULATED** | Same VFS content |

---

## Why Each Attack Vector Fails

### 1. Shell Metacharacters (`;`, `&&`, `||`, `|`, `$()`)

**Attack:** `cat /etc/passwd; whoami` — execute two commands
**Result:** `bash: cat /etc/passwd; whoami: command not found`
**Why it fails:** The command parser splits on whitespace only. The semicolon, pipe, `&&`, `||`, and `$()` are treated as literal characters in the command name. The entire string is passed to `response_engine.py` which checks it against the supported command list. Since `cat /etc/passwd; whoami` doesn't match `cat `, it falls through to `command_not_found`.

### 2. Redirects (`>`, `>>`, `<`, `2>&1`)

**Attack:** `ls > /dev/null` — suppress output
**Result:** (empty)
**Why it fails:** The `>` is not parsed as a redirect operator. The `ls` command receives the argument `>` as a literal string, which isn't a valid path. The redirect to `/dev/null` never happens. The empty output is because `ls` with no valid path returns nothing.

### 3. Glob Wildcards (`*`, `?`, `[`)

**Attack:** `ls /etc/p*` — glob-expand to `/etc/passwd`
**Result:** (empty)
**Why it fails:** The `*` is not parsed as a glob. The literal path `/etc/p*` is passed to `fs.ls()`, which doesn't find a match in the VFS dict. Returns empty.

### 4. Variable Expansion (`$HOME`, `$USER`, `$$`)

**Attack:** `echo $HOME` — leak real home directory
**Result:** `bash: echo $HOME: command not found`
**Why it fails:** `echo` is not in the supported commands list. Even if it were, the `$` is not expanded — it's treated as a literal character. The VFS doesn't have an environment variable system.

### 5. Command Substitution (`$(cmd)`, `` `cmd` ``)

**Attack:** `echo $(whoami)` — execute whoami inside echo
**Result:** `bash: echo $(whoami): command not found`
**Why it fails:** `echo` not supported. `$(whoami)` not parsed as substitution — treated as literal string in command name.

### 6. Path Traversal (`../../etc/passwd`)

**Attack:** `cat ../../etc/passwd` — escape VFS sandbox
**Result:** VFS content (same as `cat /etc/passwd`)
**Why it fails:** The `_resolve()` method in `filesystem.py` strips leading `/` and splits on `/`. `../../etc/passwd` resolves to `etc/passwd` in the VFS tree. The traversal stays within the VFS dict — there's no real filesystem to traverse into.

### 7. Absolute Paths to Real Files (`/etc/passwd`, `/proc/version`)

**Attack:** `cat /etc/passwd` — read real host file
**Result:** VFS content (4 fake entries)
**Why it fails:** The `cat` handler passes the path to `fs.cat(path)`, which does a dict lookup in the hardcoded VFS tree. It never opens a real file. The VFS has its own `/etc/passwd` with 4 fake entries.

### 8. Process/Kernel Info (`/proc/1/cmdline`, `/proc/version`)

**Attack:** `cat /proc/version` — leak kernel version
**Result:** `cat: /proc/version: No such file or directory`
**Why it fails:** `/proc` is not in the VFS tree. The `_resolve()` method returns `None`, and `cat()` returns the "No such file or directory" error.

### 9. Shell Escape (`/bin/sh`, `bash -c`, `exec`, `eval`)

**Attack:** `/bin/sh` — spawn real shell
**Result:** `bash: /bin/sh: command not found`
**Why it fails:** These aren't in the supported commands list. The `response_engine.py` only handles 7 specific commands. Everything else returns `command_not_found`. There's no `subprocess`, `os.system`, or `os.exec` anywhere in the codebase.

### 10. Newline Injection (`echo test\necho hack`)

**Attack:** Send `echo test\necho hack` as a single command
**Result:** Both SSH and Telnet handlers split input on `\n` and process each line separately. The newline is consumed by the protocol handler, not passed to the command parser. Each line is processed independently.

---

## False Positive Analysis

The initial automated scan flagged some results as `INCONCLUSIVE` or `REAL HOST OUTPUT`. After manual investigation:

| Flagged Result | Why It's a False Positive |
|---|---|
| `cat /etc/passwd` → `INCONCLUSIVE` | VFS content looks like real `/etc/passwd` but has only 4 entries. Real host has 30+ with `antony:x:1000:1000:...` |
| `cat /etc/shadow` → `INCONCLUSIVE` | VFS content has `*` (locked accounts). Real shadow has actual password hashes |
| `cat /home/antony/.ssh/id_rsa` → `REAL HOST OUTPUT` | The path `/home/antony` comes from attacker input, echoed back in error message. Not a host leak |
| `ls /root` → `INCONCLUSIVE` | VFS has exactly `README` and `flag.txt`. Real `/root` has different contents |
| `ls /home` → `INCONCLUSIVE` | VFS has `admin/` and `user/`. Real `/home` has `antony/` |
| `whoami` → `INCONCLUSIVE` | Returns `root`. Real host returns `antony`. Different values |

---

## Summary

| Category | Verdict |
|---|---|
| **Overall Containment** | **SECURE** |
| Basic command output | FAKE/SIMULATED — all hardcoded |
| Shell metacharacters | SECURE — not parsed |
| Variable expansion | SECURE — not supported |
| Command substitution | SECURE — not parsed |
| Path traversal | SECURE — stays within VFS dict |
| Absolute file reads | SECURE — VFS dict lookup, not real filesystem |
| `/proc` access | SECURE — not in VFS |
| Shell escape | SECURE — no subprocess/exec anywhere |
| Redirects | SECURE — not parsed |
| Glob wildcards | SECURE — not parsed |
| Environment variables | SECURE — no env system |
| Process information | SECURE — `/proc` not in VFS |
| Kernel version | SECURE — hardcoded fake string |

**No real host command execution was demonstrated. No shell escape is possible.**

---

## Recommendations

| # | Priority | Recommendation |
|---|---|---|
| 1 | **MEDIUM** | Add `echo` as a supported command (returns argument) — currently missing, which is unusual for a Linux shell and may fingerprint the honeypot |
| 2 | **MEDIUM** | Add more commands (`id`, `date`, `ps`, `df`, `ifconfig`, `history`, `last`, `w`, `uptime`) — the 7-command set is easily fingerprinted |
| 3 | **LOW** | Make `/etc/passwd` VFS content more realistic (add `antony:x:1000:1000:...` entry) — 4 entries is suspiciously sparse |
| 4 | **LOW** | Add `/proc/version` to VFS with a realistic kernel string |
| 5 | **LOW** | Consider adding a `~/.bash_history` file to VFS with fake commands |
| 6 | **INFO** | The VFS is well-isolated — dict-based, no file I/O, no path traversal possible |
