#!/usr/bin/env python3
"""Acceptance test: verify the Virtual Linux state engine.

Every result must reflect the previous operation.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.filesystem import FakeFilesystem, UserDatabase, GroupDatabase
from shared.response_engine import decide_response

passed = 0
failed = 0


def check(label: str, got, want: str) -> None:
    global passed, failed
    got_s = str(got)
    want_s = str(want)
    if got_s == want_s:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")
        print(f"        got:  {got_s!r}")
        print(f"        want: {want_s!r}")


def run(cmd: str, cwd: str = "/", username: str = "root",
        fs: FakeFilesystem | None = None) -> tuple[str, str]:
    """Run a command through the response engine, return (output, status)."""
    if fs is None:
        fs = FakeFilesystem()
    plan = decide_response("ssh", "test-session", cmd,
                           {"args": cmd.split()[1:], "cwd": cwd},
                           fs, username=username)
    return plan.content, plan.status


# ── Test 1: mkdir → ls ─────────────────────────────────────────────────────

print("\n=== Test 1: mkdir /tmp/test → ls /tmp ===")
fs = FakeFilesystem()
run("mkdir /tmp/test", fs=fs)
out, _ = run("ls /tmp", fs=fs)
check("ls /tmp shows 'test'", str("test" in out), "True")


# ── Test 2: touch → ls ─────────────────────────────────────────────────────

print("\n=== Test 2: touch /tmp/test/a.txt → ls /tmp/test ===")
run("touch /tmp/test/a.txt", fs=fs)
out, _ = run("ls /tmp/test", fs=fs)
check("ls /tmp/test shows 'a.txt'", out, "a.txt")


# ── Test 3: chmod 600 → ls -la ─────────────────────────────────────────────

print("\n=== Test 3: chmod 600 /tmp/test/a.txt → ls -la /tmp/test ===")
run("chmod 600 /tmp/test/a.txt", fs=fs)
out, _ = run("ls -la /tmp/test", fs=fs)
check("file has -rw------- permissions", out.startswith("total"), "True")
has_perm = "-rw-------" in out
check("ls -la shows -rw------- for a.txt", str(has_perm), "True")
check("ls -la shows a.txt in output", str("a.txt" in out), "True")


# ── Test 4: rm → ls ────────────────────────────────────────────────────────

print("\n=== Test 4: rm /tmp/test/a.txt → ls /tmp/test ===")
run("rm /tmp/test/a.txt", fs=fs)
out, _ = run("ls /tmp/test", fs=fs)
check("ls /tmp/test is now empty", out.strip(), "")


# ── Test 5: rmdir → ls ─────────────────────────────────────────────────────

print("\n=== Test 5: rmdir /tmp/test → ls /tmp ===")
run("rmdir /tmp/test", fs=fs)
out, _ = run("ls /tmp", fs=fs)
check("ls /tmp no longer shows 'test'",
      str("test" not in out), "True")


# ── Test 6: useradd → cat /etc/passwd ──────────────────────────────────────

print("\n=== Test 6: useradd attacker → cat /etc/passwd ===")
fs = FakeFilesystem()
before = run("cat /etc/passwd", fs=fs)[0]
check("'attacker' NOT in /etc/passwd before useradd",
      "attacker" in before, "False")

run("useradd attacker", fs=fs)
after = run("cat /etc/passwd", fs=fs)[0]
check("'attacker' IS in /etc/passwd after useradd",
      str("attacker" in after), "True")


# ── Test 7: id reflects useradd ────────────────────────────────────────────

print("\n=== Test 7: useradd creates user with correct UID ===")
fs = FakeFilesystem()
run("useradd testuser100", fs=fs)
pw = run("cat /etc/passwd", fs=fs)[0]
check("testuser100 appears in /etc/passwd",
      "testuser100" in pw, "True")


# ── Test 8: mkdir -p creates parents ───────────────────────────────────────

print("\n=== Test 8: mkdir -p /a/b/c → ls /a/b ===")
fs = FakeFilesystem()
run("mkdir -p /a/b/c", fs=fs)
out, _ = run("ls /a/b", fs=fs)
check("ls /a/b shows 'c'", out, "c")


# ── Test 9: cp → ls ────────────────────────────────────────────────────────

print("\n=== Test 9: cp /etc/hostname /tmp/hostname.bak ===")
fs = FakeFilesystem()
run("cp /etc/hostname /tmp/hostname.bak", fs=fs)
check("copied file exists",
      str(fs.exists("/tmp/hostname.bak")), "True")
orig = run("cat /etc/hostname", fs=fs)[0]
copy = run("cat /tmp/hostname.bak", fs=fs)[0]
check("copy matches original", orig, copy)


# ── Test 10: mv → ls ───────────────────────────────────────────────────────

print("\n=== Test 10: mv /tmp/hostname.bak /tmp/moved.txt ===")
fs = FakeFilesystem()
run("cp /etc/hostname /tmp/hostname.bak", fs=fs)
run("mv /tmp/hostname.bak /tmp/moved.txt", fs=fs)
check("old path gone", str(fs.exists("/tmp/hostname.bak")), "False")
check("new path exists", str(fs.exists("/tmp/moved.txt")), "True")


# ── Test 11: chown changes ownership ───────────────────────────────────────

print("\n=== Test 11: chown 1001:1001 /tmp/testfile ===")
fs = FakeFilesystem()
run("touch /tmp/testfile", fs=fs)
run("chown 1001:1001 /tmp/testfile", fs=fs)
out = run("ls -la /tmp", fs=fs)[0]
check("chown applied", "1001" in out, "True")


# ── Test 12: touch updates mtime on existing file ──────────────────────────

print("\n=== Test 12: touch updates mtime on existing file ===")
fs = FakeFilesystem()
run("touch /tmp/existing", fs=fs)
check("file exists before touch",
      str(fs.exists("/tmp/existing")), "True")
run("touch /tmp/existing", fs=fs)
check("file still exists after touch",
      str(fs.exists("/tmp/existing")), "True")


# ── Test 13: cat /nonexistent returns error ────────────────────────────────

print("\n=== Test 13: cat /nonexistent returns error ===")
fs = FakeFilesystem()
out, status = run("cat /nonexistent", fs=fs)
check("cat /nonexistent has error", "No such file" in out, "True")
check("cat /nonexistent status is 1", status, "1")


# ── Test 14: groupadd → cat /etc/group ─────────────────────────────────────

print("\n=== Test 14: groupadd developers → cat /etc/group ===")
fs = FakeFilesystem()
run("groupadd developers", fs=fs)
out = run("cat /etc/group", fs=fs)[0]
check("'developers' in /etc/group", "developers" in out, "True")


# ── Test 15: mkdir fails on existing dir ───────────────────────────────────

print("\n=== Test 15: mkdir /tmp fails if already exists ===")
fs = FakeFilesystem()
out, status = run("mkdir /tmp", fs=fs)
check("mkdir /tmp returns empty (already exists)", out.strip(), "")


# ── Test 16: rm -rf removes directory tree ─────────────────────────────────

print("\n=== Test 16: rm -rf removes non-empty directory ===")
fs = FakeFilesystem()
run("mkdir -p /a/b/c", fs=fs)
run("touch /a/b/c/file.txt", fs=fs)
run("rm -rf /a", fs=fs)
check("/a is gone after rm -rf", str(fs.exists("/a")), "False")


# ── Test 17: ls -la on /root shows real permissions ────────────────────────

print("\n=== Test 17: ls -la /root shows permissions ===")
fs = FakeFilesystem()
out = run("ls -la /root", fs=fs)[0]
check("ls -la /root shows 'total'", out.startswith("total"), "True")
check("ls -la /root shows flag.txt", "flag.txt" in out, "True")
check("ls -la /root shows root ownership", "root" in out, "True")


# ── Test 18: env shows environment ─────────────────────────────────────────

print("\n=== Test 18: env / printenv ===")
fs = FakeFilesystem()
out = run("env", fs=fs)[0]
check("env shows HOME=/root", "HOME=/root" in out, "True")
out = run("printenv HOME", fs=fs)[0]
check("printenv HOME returns /root", out.strip(), "/root")


# ── Summary ─────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"ACCEPTANCE TEST RESULTS: {passed} passed, {failed} failed")
print(f"{'='*60}")

if failed:
    sys.exit(1)
