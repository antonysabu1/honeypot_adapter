"""Shell command-line sequencing: `;`, `&&` and `||`.

Answers decide_line() only (no transports), so it runs anywhere:

    python3 test_chaining.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared.filesystem import FakeFilesystem
from shared.response_engine import decide_line, is_chained

ROOT = "/root"
failures = []


def check(line, expect_content, expect_status, expect_cwd=ROOT,
          expect_type=None, username="root", label=""):
    plan, cwd = decide_line(
        "ssh", "sid", line, {"args": line.split()[1:], "cwd": ROOT},
        FakeFilesystem(), username=username,
    )
    problems = []
    if plan.content != expect_content:
        problems.append(f"content={plan.content!r} want {expect_content!r}")
    if plan.status != expect_status:
        problems.append(f"status={plan.status!r} want {expect_status!r}")
    if cwd != expect_cwd:
        problems.append(f"cwd={cwd!r} want {expect_cwd!r}")
    if expect_type and plan.response_type != expect_type:
        problems.append(f"type={plan.response_type!r} want {expect_type!r}")
    if problems:
        failures.append(f"{label or line!r}: " + "; ".join(problems))
        print(f"FAIL {label or line!r}: " + "; ".join(problems))
    else:
        print(f"ok   {label or line!r}")


def check_chained(line, expected, label=""):
    got = is_chained(line)
    if got != expected:
        failures.append(f"is_chained({line!r}) = {got}, want {expected}")
        print(f"FAIL is_chained({line!r}) = {got}, want {expected}")
    else:
        print(f"ok   is_chained({line!r}) = {got}")


UID = "uid=0(root) gid=0(root) groups=0(root)"
UNAME = ("Linux honeypot 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 "
         "09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux")

# --- `;` runs every segment and yields the last status ---------------------
check("id; uname -a", f"{UID}\n{UNAME}", "0")
check("id; bogus", f"{UID}\nbash: bogus: command not found", "127",
      expect_type="command_not_found")
check("id; bogus; whoami", f"{UID}\nbash: bogus: command not found\nroot", "0")
check("id;", UID, "0", label="trailing separator")
check("id && ", UID, "0", label="trailing &&")
check(";", "", "0", label="separator only")

# --- `&&` stops at the first failure --------------------------------------
check("bogus && id", "bash: bogus: command not found", "127",
      expect_type="command_not_found", label="&& short-circuits")
check("id && whoami", f"{UID}\nroot", "0")

# --- `||` runs after a failure and is skipped after a success -------------
check("bogus || whoami", "bash: bogus: command not found\nroot", "0")
check("id || whoami", UID, "0", label="|| skipped on success")
check("bogus || id || whoami", f"bash: bogus: command not found\n{UID}", "0")

# --- exit status follows the last segment actually executed ---------------
check("bogus && id", "bash: bogus: command not found", "127",
      label="status is the failing segment")

# --- `cd` inside a chain moves the cwd and is handed back -----------------
check("cd /tmp && pwd", "/tmp", "0", expect_cwd="/tmp")
check("cd /tmp; cd /etc; pwd", "/etc", "0", expect_cwd="/etc")
check("cd /nonexistent && id", "bash: cd: /nonexistent: No such file or directory",
      "1", expect_cwd=ROOT, expect_type="cd_failed")
check("cd /nonexistent || pwd", "bash: cd: /nonexistent: No such file or directory\n/root",
      "0", expect_cwd=ROOT)
check("cd /etc && cd .. && pwd", "/", "0", expect_cwd="/")

# --- login user survives into chained segments ----------------------------
check("whoami; id", f"alice\n{UID}", "0", username="alice")

# --- exit inside a chain ends the session ---------------------------------
check("id; exit", "logout", "0", expect_type="session_end")

# --- separators inside quotes are literal; pipelines are not chaining -----
check_chained('echo "a;b"', False)
check_chained("echo 'x || y'", False)
check_chained("cat /etc/passwd | head -2", False)
check_chained("id; uname -a", True)
check_chained("id && id", True)
check_chained("id", False)

print()
if failures:
    print(f"=== {len(failures)} CHAINING TEST(S) FAILED ===")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("=== ALL CHAINING TESTS PASSED ===")
