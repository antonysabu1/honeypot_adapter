#!/usr/bin/env python3
"""Regression suite for the Virtual Group System.

Exercises the group-state layer through the response engine's real commands and
asserts that user, group, /etc/passwd and /etc/group state never disagree.
Nothing here touches the host: only the in-memory FakeFilesystem is mutated.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.filesystem import FakeFilesystem
from shared.response_engine import decide_response

passed = 0
failed = 0


def check(label: str, got, want) -> None:
    global passed, failed
    if str(got) == str(want):
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")


def run(fs: FakeFilesystem, cmd: str, username: str = "root"):
    """Run one command, returning (content, status)."""
    plan = decide_response(
        "ssh", "test-session", cmd,
        {"args": cmd.split()[1:], "cwd": "/"}, fs, username=username,
    )
    return plan.content, plan.status


def group_lines(fs: FakeFilesystem) -> dict[str, str]:
    out = {}
    for line in fs.cat("/etc/group").splitlines():
        if line:
            out[line.split(":")[0]] = line
    return out


def passwd_lines(fs: FakeFilesystem) -> dict[str, str]:
    out = {}
    for line in fs.cat("/etc/passwd").splitlines():
        if line:
            out[line.split(":")[0]] = line
    return out


# ── 1. groupadd creates real state ─────────────────────────────────────────

print("\n=== 1: groupadd creates state and /etc/group line ===")
fs = FakeFilesystem()
out, status = run(fs, "groupadd devs")
check("groupadd status 0", status, "0")
check("groupadd prints nothing", out, "")
check("state: group exists", fs.groups.exists("devs"), True)
check("/etc/group has devs", "devs" in group_lines(fs), True)
check("/etc/group line shape", group_lines(fs)["devs"].count(":"), 3)
check("gid is auto-allocated from 1000", fs.groups.gid("devs"), 1001)


# ── 2. duplicate / invalid / colliding gid ────────────────────────────────

print("\n=== 2: groupadd validation ===")
out, status = run(fs, "groupadd devs")
check("duplicate rejected with status 9", status, "9")
check("duplicate message", "already exists" in out, True)
out, status = run(fs, "groupadd -g 5000 ops")
check("explicit gid accepted", (status, fs.groups.gid("ops")), ("0", 5000))
out, status = run(fs, "groupadd -g 5000 clash")
check("gid collision rejected with status 4", status, "4")
check("gid collision message", "GID '5000' already exists" in out, True)
out, status = run(fs, "groupadd bad:name")
check("invalid name rejected with status 3", status, "3")
check("invalid name not created", fs.groups.exists("bad:name"), False)
out, status = run(fs, "groupadd")
check("missing operand status 1", status, "1")


# ── 3. useradd keeps primary group consistent across both files ───────────

print("\n=== 3: useradd → primary group consistency ===")
fs = FakeFilesystem()
run(fs, "useradd bob")
pw = passwd_lines(fs)["bob"]
gr = group_lines(fs)["bob"]
pw_gid = pw.split(":")[3]
check("passwd gid equals group line gid", gr.split(":")[2], pw_gid)
check("primary group name matches username", gr.split(":")[0], "bob")
check("primary member NOT listed in /etc/group members", gr.split(":")[3], "")
check("in-range uid allocated", int(pw.split(":")[2]) >= 1000, True)
out, _ = run(fs, "useradd -d /home/ann ann")
check("-d value not mistaken for the username", passwd_lines(fs)["ann"].split(":")[2], "1002")
check("home honoured", passwd_lines(fs)["ann"].split(":")[5], "/home/ann")


# ── 4. usermod -aG / -G and immediate observation ─────────────────────────

print("\n=== 4: usermod membership and immediate state ===")
fs = FakeFilesystem()
run(fs, "useradd bob")
run(fs, "groupadd devs")
run(fs, "groupadd ops")
out, status = run(fs, "usermod -aG devs bob")
check("usermod -aG status 0", status, "0")
check("/etc/group members updated", group_lines(fs)["devs"].split(":")[3], "bob")
check("id observes new group immediately",
      run(fs, "id", "bob")[0],
      f"uid=1001(bob) gid=1001(bob) groups=1001(bob),1002(devs)")
check("groups observes new group immediately",
      run(fs, "groups bob")[0], "bob : bob devs")
run(fs, "usermod -aG ops bob")
check("append keeps earlier membership",
      run(fs, "groups bob")[0], "bob : bob devs ops")
run(fs, "usermod -G ops bob")
check("-G replaces membership", run(fs, "groups bob")[0], "bob : bob ops")
check("replaced group is empty in /etc/group", group_lines(fs)["devs"].split(":")[3], "")
out, status = run(fs, "usermod -G nosuch bob")
check("unknown group rejected", status, "6")
out, status = run(fs, "usermod -G devs ghost")
check("unknown user rejected", status, "6")
check("failed usermod left state untouched",
      run(fs, "groups bob")[0], "bob : bob ops")


# ── 5. bare `groups` reflects the login identity ──────────────────────────

print("\n=== 5: groups with no argument uses the login user ===")
fs = FakeFilesystem()
run(fs, "useradd bob")
run(fs, "groupadd devs")
run(fs, "usermod -aG devs bob")
check("bare groups as bob", run(fs, "groups", "bob")[0], "bob devs")
check("bare groups as root", run(fs, "groups")[0], "root")
out, status = run(fs, "groups ghost")
check("unknown user in argument", status, "1")
check("unknown user message", "no such user" in out, True)
check("id names the user argument, not the login user",
      run(fs, "id bob")[0],
      "uid=1001(bob) gid=1001(bob) groups=1001(bob),1002(devs)")
out, status = run(fs, "id ghost")
check("id unknown user status 1", status, "1")
check("id unknown user message", "no such user" in out, True)


# ── 6. groupdel rules ─────────────────────────────────────────────────────

print("\n=== 6: groupdel rules ===")
fs = FakeFilesystem()
run(fs, "useradd bob")
run(fs, "groupadd devs")
out, status = run(fs, "groupdel devs")
check("deleting an empty group works", status, "0")
check("group gone from state", fs.groups.exists("devs"), False)
check("group gone from /etc/group", "devs" in group_lines(fs), False)
out, status = run(fs, "groupdel bob")
check("primary group cannot be deleted", status, "8")
check("primary-group message", "primary group of user 'bob'" in out, True)
out, status = run(fs, "groupdel ghost")
check("missing group status 6", status, "6")


# ── 7. userdel leaves no dangling membership ──────────────────────────────

print("\n=== 7: userdel cleans every reference ===")
fs = FakeFilesystem()
run(fs, "useradd bob")
run(fs, "groupadd devs")
run(fs, "usermod -aG devs bob")
out, status = run(fs, "userdel bob")
check("userdel status 0", status, "0")
check("user gone from /etc/passwd", "bob" in passwd_lines(fs), False)
check("private group removed", fs.groups.exists("bob"), False)
check("supplementary membership removed", group_lines(fs)["devs"].split(":")[3], "")
check("no user remains a member anywhere", fs.groups.memberships_for("bob"), [])


# ── 8. regression: existing user behaviour is unchanged ───────────────────

print("\n=== 8: Virtual User System regression ===")
fs = FakeFilesystem()
check("root id unchanged", run(fs, "id")[0],
      "uid=0(root) gid=0(root) groups=0(root)")
check("whoami reflects login user", run(fs, "whoami", "admin")[0], "admin")
out, status = run(fs, "useradd dup")
out, status = run(fs, "useradd dup")
check("duplicate user still rejected", status, "9")
check("/etc/passwd still built from state",
      "root:x:0:0:root:/root:/bin/bash" in run(fs, "cat /etc/passwd")[0], True)
check("/etc/group line count equals group count",
      len([l for l in fs.cat("/etc/group").splitlines() if l]),
      len(fs.groups.all_names()))


print(f"\n{'='*60}")
print(f"GROUP TEST RESULTS: {passed} passed, {failed} failed")
print(f"{'='*60}")
if failed:
    sys.exit(1)
