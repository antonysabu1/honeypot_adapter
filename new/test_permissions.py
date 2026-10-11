"""Virtual filesystem access control, driven through the real engine surface.

The single decision point is ``shared/permissions.py``; these tests assert what
the *engine* answers (``decide_response``/``decide_line``), because that is what
an attacker's session actually sees.  All identities are virtual: a user added
to the virtual database is a non-root process, ``root``/an unknown login is the
honeypot's presented root shell.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.response_engine import decide_response, decide_line
from shared.filesystem import FakeFilesystem
from shared.permissions import identity_for

ROOT = "/"
FAIL = 0
NO = 0
YES = 0


def check(label, cond):
    global FAIL
    mark = "ok" if cond else "FAIL"
    if not cond:
        FAIL += 1
    print(f"  [{mark}] {label}")


def run(fs, cmd, user="bob"):
    return decide_response("ssh", "s", cmd, {"args": cmd.split()[1:], "cwd": "/"}, fs, username=user)


def line(fs, cmd, user="bob"):
    plan, _cwd = decide_line("ssh", "s", cmd, {"args": [], "cwd": "/"}, fs, username=user)
    return plan


def scene():
    """A filesystem with a non-root user `bob` and a shared group."""
    fs = FakeFilesystem()
    fs.users.add("bob", uid=2000, gid=2000)
    fs.groups.add("shared", gid=2050)
    fs.groups.add_user_to_group("bob", "shared")
    # An unwritable root: /etc (755 root) is the classic target.
    fs.write_file("/tmp/rootfile", "root only\n", mode=0o644)
    fs.write_file("/tmp/sharedfile", "group secret\n", mode=0o640)
    fs.chown("/tmp/sharedfile", gid=2050)
    fs.write_file("/tmp/otherfile", "other secret\n", mode=0o640)
    fs.chown("/tmp/otherfile", gid=9999)
    fs.mkdir("/tmp/lockdir", mode=0o600)
    fs.write_file("/tmp/lockdir/inside", "hidden\n", mode=0o644)
    return fs


print("== identity model ==")
fs = scene()
ident = identity_for(fs, "bob")
check("bob is non-root", not ident.is_root and ident.uid == 2000)
check("bob sees supplementary group", 2050 in ident.groups)
check("unknown login is presented as root", identity_for(fs, "ghost").is_root)
check("root login is root", identity_for(fs, "root").is_root)

print("== owner / other read ==")
check("root reads /root/flag.txt", "flag{" in run(fs, "cat /root/flag.txt", "root").content)
check("bob is denied /root/flag.txt", "Permission denied" in run(fs, "cat /root/flag.txt").content)
check("denial does not end the session", run(fs, "cat /root/flag.txt").response_type != "session_end")
check("bob reads a world-readable file", "root" in run(fs, "cat /etc/passwd").content)

print("== group read ==")
check("bob reads a file his group can read", "group secret" in run(fs, "cat /tmp/sharedfile").content)
check("bob denied a file for another group", "Permission denied" in run(fs, "cat /tmp/otherfile").content)

print("== directory execute (traversal) ==")
check("bob denied listing a 0600 dir", "Permission denied" in run(fs, "ls /tmp/lockdir").content)
check("bob denied reading through a 0600 dir", "Permission denied" in run(fs, "cat /tmp/lockdir/inside").content)
check("bob denied stat through a 0600 dir", "Permission denied" in run(fs, "stat /tmp/lockdir/inside").content)
check("bob can list /tmp (1777)", run(fs, "ls /tmp").status == "0")

print("== create / remove ==")
check("bob denied mkdir in /etc", "Permission denied" in run(fs, "mkdir /etc/evil").content)
check("bob denied touch in /etc", "Permission denied" in run(fs, "touch /etc/evil").content)
check("bob allowed mkdir in /tmp", run(fs, "mkdir /tmp/bobdir").status == "0")
check("bob allowed touch in /tmp", run(fs, "touch /tmp/bobfile").status == "0")
check("bob allowed rm of his own /tmp file", run(fs, "rm /tmp/bobfile").status == "0")
check("sticky bit protects root file in /tmp", "Permission denied" in run(fs, "rm /tmp/rootfile").content)
check("root may remove anything in /tmp", run(fs, "rm /tmp/rootfile", "root").status == "0")

print("== chmod / chown ==")
check("bob denied chmod of a root file", "Operation not permitted" in run(fs, "chmod 777 /etc/passwd").content)
fs2 = scene()
run(fs2, "mkdir /tmp/bobown")
check("bob owns the directory he created", run(fs2, "chmod 600 /tmp/bobown").status == "0")
run(fs2, "touch /tmp/ownfile")
check("bob may chmod a file he owns", run(fs2, "chmod 640 /tmp/ownfile").status == "0")
check("bob denied chown to root uid", "Operation not permitted" in run(fs2, "chown 0 /tmp/ownfile").content)
check("root may chown", run(fs2, "chown 0 /tmp/ownfile", "root").status == "0")

print("== cp / mv / ln ==")
check("bob denied cp of a root file", "Permission denied" in run(fs, "cp /root/flag.txt /tmp/x").content)
check("bob denied mv of a root file", "Permission denied" in run(fs, "mv /root/flag.txt /tmp/x").content)
check("bob denied ln into /etc", "Permission denied" in run(fs, "ln -s /etc/passwd /etc/link").content)

print("== ln cannot launder an unreadable file (audit reproduction) ==")
fs3 = scene()
check("control: bob cannot cat the flag", "Permission denied" in run(fs3, "cat /root/flag.txt").content)
ln = run(fs3, "ln /root/flag.txt /tmp/loot")
check("hard link to an unreadable file is denied", "Permission denied" in ln.content)
check("no loot file was created", not fs3.exists("/tmp/loot"))
check("the flag is not disclosed through a link", "flag{" not in run(fs3, "cat /tmp/loot").content)
check("ln of a readable file is still allowed", run(fs3, "ln /etc/hostname /tmp/host.name").status == "0")
check("root may hard-link the flag", run(fs3, "ln /root/flag.txt /tmp/rootloot", "root").status == "0")

print("== find does not disclose unlistable directories ==")
fs4 = scene()
found = run(fs4, "find -name flag.txt")
check("bob's find omits /root", "/root/flag.txt" not in found.content)
check("root's find still sees /root", "/root/flag.txt" in run(fs4, "find -name flag.txt", "root").content)

print("== account administration requires virtual root ==")
fs5 = scene()
for cmd in ("useradd evil", "userdel bob", "groupadd evild",
            "groupdel shared", "usermod -aG shared bob"):
    r = run(fs5, cmd)
    check(f"bob denied {cmd}", "Permission denied" in r.content and r.response_type != "session_end")
check("no user was created", fs5.users.get("evil") is None)
check("no group was created", not fs5.groups.exists("evild"))
check("shared still exists", fs5.groups.exists("shared"))
check("root may useradd", run(fs5, "useradd carol", "root").status == "0")
check("root's useradd created the account", fs5.users.get("carol") is not None)

print("== redirection writes ==")
check("bob denied redirect into /etc", "Permission denied" in line(fs, "echo x > /etc/passwd").content)
check("bob allowed redirect into /tmp", line(fs, "echo x > /tmp/bobout").status == "0")
check("bob denied append into /etc", "Permission denied" in line(fs, "echo x >> /etc/passwd").content)

print("== package manager ==")
check("bob denied apt-get install", run(fs, "apt-get install bash").status == "100")
check("bob denied apt-get remove", run(fs, "apt-get remove bash").status == "100")
check("bob denied apt purge", run(fs, "apt purge bash").status == "100")
check("root passes the apt permission gate", run(fs, "apt-get install bash", "root").status != "100")

print("== sequencing keeps its exit status and access policy ==")
plan = line(fs, "id; cat /root/flag.txt")
check("chained denial is not a session end", plan.response_type != "session_end")
check("chained output carries both segments", "uid=" in plan.content and "Permission denied" in plan.content)
check("&& short-circuits on the denied status", "whoami" not in line(fs, "cat /root/flag.txt && whoami").content)
check("root bypasses every check", run(fs, "cat /root/flag.txt && id", "root").status == "0")

print()
if FAIL:
    print(f"{FAIL} check(s) FAILED")
    sys.exit(1)
print("all permission checks passed")
