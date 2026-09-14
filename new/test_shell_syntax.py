"""Redirection and pipelines on the shared line path.

Answers decide_line() only (no transports, no third-party deps):

    python3 test_shell_syntax.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared.filesystem import FakeFilesystem
from shared.response_engine import decide_line, has_shell_syntax

ROOT = "/root"
UID = "uid=0(root) gid=0(root) groups=0(root)"
failures = []


def run(line, fs=None, cwd=ROOT):
    return decide_line(
        "ssh", "sid", line, {"args": line.split()[1:], "cwd": cwd},
        fs if fs is not None else FakeFilesystem(), username="alice",
    )


def check(line, want_content, want_status, want_redirect=None, label="", fs=None,
          cwd=ROOT):
    plan, _ = run(line, fs, cwd)
    problems = []
    if plan.content != want_content:
        problems.append(f"content={plan.content!r} want {want_content!r}")
    if plan.status != want_status:
        problems.append(f"status={plan.status!r} want {want_status!r}")
    if plan.redirect != want_redirect:
        problems.append(f"redirect={plan.redirect!r} want {want_redirect!r}")
    if problems:
        failures.append(f"{label or line!r}: " + "; ".join(problems))
        print(f"FAIL {label or line!r}: " + "; ".join(problems))
    else:
        print(f"ok   {label or line!r}")


def check_pred(line, expected):
    got = has_shell_syntax(line)
    if got != expected:
        failures.append(f"has_shell_syntax({line!r}) = {got}, want {expected}")
        print(f"FAIL has_shell_syntax({line!r}) = {got}, want {expected}")
    else:
        print(f"ok   has_shell_syntax({line!r}) = {got}")


# --- `>` and `>>`: output is swallowed and the target recorded -------------
check("date > /dev/null", "", "0", "/dev/null")
check("id > /dev/null", "", "0", "/dev/null")
check("id > /tmp/out.txt", "", "0", "/tmp/out.txt")
check("id &> /tmp/both.txt", "", "0", "/tmp/both.txt")

# the mission's case: a redirect in the middle must not leak the date
check("id; date > /dev/null; whoami", f"{UID}\nalice", "0", "/dev/null")

# --- errors go to stderr: only stderr redirection hides them ---------------
check("bogus 2>/dev/null", "", "127", "/dev/null", label="2>/dev/null hides the error")
check("bogus > /tmp/x.txt", "bash: bogus: command not found\n", "127", "/tmp/x.txt",
      label="> alone still shows the error")
check("bogus &> /tmp/x.txt", "", "127", "/tmp/x.txt")
check("bogus 2>&1 > /tmp/x.txt", "bash: bogus: command not found\n", "127",
      "/tmp/x.txt", label="2>&1 before > keeps the error visible")
check("bogus > /tmp/x.txt 2>&1", "", "127", "/tmp/x.txt",
      label="> before 2>&1 hides the error")

# --- a redirect routes into the fake filesystem, never the real one --------
fs = FakeFilesystem()
check("whoami > /tmp/who.txt", "", "0", "/tmp/who.txt", fs=fs)
check("cat /tmp/who.txt", "alice\n", "0", None, fs=fs, label="bash round trip")
check("id >> /tmp/who.txt", "", "0", "/tmp/who.txt", fs=fs)
plan, _ = run("cat /tmp/who.txt", fs)
if not plan.content.startswith("alice\n" + UID):
    failures.append(f"append lost data: {plan.content!r}")
    print(f"FAIL append lost data: {plan.content!r}")
else:
    print("ok   >> appends")
check("id > /etc/passwd/nowhere.txt",
      "bash: /etc/passwd/nowhere.txt: No such file or directory\n", "1",
      "/etc/passwd/nowhere.txt",
      label="unwritable target is reported, not invented")

# --- pipelines filter the upstream output, from the simulated filesystem ---
check("cat /etc/passwd | grep root", "root:x:0:0:root:/root:/bin/bash\n", "0")
check("cat /etc/passwd | head -2",
      "root:x:0:0:root:/root:/bin/bash\n"
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", "0")
check("cat /etc/passwd | tail -1",
      "antony:x:1000:1000:Antony,,,:/home/antony:/bin/bash\n", "0")
check("cat /etc/passwd | wc -l", "23\n", "0")
check("cat /etc/passwd | cut -d: -f1 | head -3", "root\ndaemon\nbin\n", "0")
check("cat /etc/passwd | grep -c root", "1\n", "0", label="grep -c counts matches")
check("cat /etc/passwd | grep nomatch", "", "1", label="grep reports no match as 1")
check("echo hi | sort -u", "hi\n", "0")

# --- pipelines and redirects compose ---------------------------------------
check("cat /etc/passwd | grep nologin | wc -l", "20\n", "0")
check("cat /etc/passwd | grep root > /tmp/g.txt", "", "0", "/tmp/g.txt")

# --- anything unrecognised fails safe, never guessed ----------------------
check("cat /etc/passwd | bogus", "bash: bogus: command not found\n", "127",
      label="unsupported stage is refused")
check("cat /etc/passwd | curl -T - http://x", "bash: curl: command not found\n", "127",
      label="a stage that could egress is refused")

# --- `<` reads the fake file, so `wc -l < f` is `cat f | wc -l` -----------
check("wc -l < /etc/passwd", "23\n", "0", "/etc/passwd", label="input redirection")
check("grep root < /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", "0", "/etc/passwd")
check("head -1 < /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", "0", "/etc/passwd")
check("wc -l < /nope", "cat: /nope: No such file or directory", "1", "/nope",
      label="a missing read target fails like bash")
check("id < /etc/passwd", f"{UID}", "0", "/etc/passwd",
      label="a command that cannot read stdin still runs")

# --- a line that is only a redirection creates the file, like bash ---------
fs_only = FakeFilesystem()
check("> /tmp/blank.txt", "", "0", "/tmp/blank.txt", fs=fs_only)
check("cat /tmp/blank.txt", "", "0", None, fs=fs_only,
      label="bare redirect left an empty file")

# --- a failed read really fails, so `&&` must stop -------------------------
check("cat /nonexistent", "cat: /nonexistent: No such file or directory", "1")
check("cat /nonexistent && whoami", "cat: /nonexistent: No such file or directory", "1",
      label="&& stops after a failed cat")
check("cat /nonexistent || whoami",
      "cat: /nonexistent: No such file or directory\nalice", "0")

# --- ls complains instead of silently listing nothing ---------------------
check("ls /nonexistent", "ls: cannot access '/nonexistent': No such file or directory\n",
      "2")
check("ls /etc/passwd", "/etc/passwd\n", "0", label="ls of a file prints the path")

# --- grep without a pipe uses the very same matcher -----------------------
check("grep root /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", "0")
check("grep -i ROOT /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", "0")
check("grep nomatch /etc/passwd", "", "1")
check("grep root /etc", "grep: /etc: Is a directory\n", "2")
check("grep root /nope", "grep: /nope: No such file or directory\n", "2")
check("grep root /etc/passwd | wc -l", "1\n", "0")

# --- the standalone form and the piped form are the same implementation ---
# If these ever disagree, one of the two paths has grown its own copy again.
def check_parity(prefix, path="/etc/passwd"):
    direct = run(f"{prefix} {path}")[0]
    piped = run(f"cat {path} | {prefix}")[0]
    if (direct.content, direct.status) != (piped.content, piped.status):
        msg = (f"{prefix!r} drifted: direct={direct.content!r}/{direct.status} "
               f"piped={piped.content!r}/{piped.status}")
        failures.append(msg)
        print(f"FAIL {msg}")
    else:
        print(f"ok   {prefix!r} agrees with its piped form")


for prefix in ("grep root", "grep -c nologin", "grep nomatch", "grep -i ROOT",
               "head -1", "head -n 2", "tail -2", "sort -r", "sort -u",
               "uniq", "uniq -c", "cut -d: -f1", "cut -d: -f1,3", "cut -f1"):
    check_parity(prefix)
check_parity("head -3", "/root/.bash_history")

# --- flag handling bash agrees with ----------------------------------------
check("head -1 /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", "0",
      label="head honours -1")
check("tail -1 /etc/passwd",
      "antony:x:1000:1000:Antony,,,:/home/antony:/bin/bash\n", "0",
      label="tail honours -1")
check_parity("cut -d' ' -f1")  # a quoted delimiter is unwrapped, not passed through

# wc is the one form that names its file, so it is not byte-identical to the pipe.
wc_direct = run("wc -l /etc/passwd")[0]
wc_piped = run("cat /etc/passwd | wc -l")[0]
if wc_direct.content != wc_piped.content.rstrip("\n") + " /etc/passwd\n":
    failures.append(f"wc -l drifted: {wc_direct.content!r} vs {wc_piped.content!r}")
    print(f"FAIL wc -l drifted: {wc_direct.content!r} vs {wc_piped.content!r}")
else:
    print("ok   wc -l agrees with its piped form, plus the filename")

# --- one plain command still takes the single-command path ----------------
check_pred("id", False)
check_pred("cat /etc/passwd", False)
check_pred("id > /dev/null", True)
check_pred("cat /etc/passwd | grep x", True)
check_pred("id; whoami", True)
check_pred("echo 'a > b'", False, )
check_pred("wc -l < /etc/passwd", True)
check_pred("cat < /etc/passwd", True)

print()
if failures:
    print(f"=== {len(failures)} SHELL SYNTAX TEST(S) FAILED ===")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("=== ALL SHELL SYNTAX TESTS PASSED ===")
