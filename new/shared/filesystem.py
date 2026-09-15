"""Stateful virtual Linux filesystem with inode-based metadata.

Every file and directory carries mode, uid, gid, and timestamps.  All mutations
(mkdir, touch, rm, chmod, chown, cp, mv) operate on this tree so that every
command observes the results of every previous command.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone

_BOOT = datetime(2026, 9, 8, 10, 42, 13, tzinfo=timezone.utc)


class FilesystemError(Exception):
    pass


@dataclass
class Inode:
    is_dir: bool
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    content: str = ""
    children: dict[str, Inode] = field(default_factory=dict)
    mtime: datetime = field(default_factory=lambda: _BOOT)
    ctime: datetime = field(default_factory=lambda: _BOOT)


# ── User / Group databases ──────────────────────────────────────────────────

_PASSWD_HEADER = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
    "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
    "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
    "messagebus:x:102:104::/nonexistent:/usr/sbin/nologin\n"
    "sshd:x:103:65534::/run/sshd:/usr/sbin/nologin\n"
    "antony:x:1000:1000:Antony,,,:/home/antony:/bin/bash\n"
)

_SHADOW_HEADER = (
    "root:*:19840:0:99999:7:::\n"
    "daemon:*:19840:0:99999:7:::\n"
    "bin:*:19840:0:99999:7:::\n"
    "sys:*:19840:0:99999:7:::\n"
    "sshd:*:19840:0:99999:7:::\n"
    "antony:!:19840:0:99999:7:::\n"
)

_GROUP_HEADER = (
    "root:x:0:\n"
    "daemon:x:1:\n"
    "bin:x:2:\n"
    "sys:x:3:\n"
    "adm:x:4:antony\n"
    "sudo:x:27:antony\n"
    "antony:x:1000:\n"
)


@dataclass
class _UserEntry:
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


@dataclass
class _GroupEntry:
    gid: int
    members: list[str]


class UserDatabase:
    def __init__(self) -> None:
        self._users: dict[str, _UserEntry] = {}
        self._parse(_PASSWD_HEADER)

    # ── parsing ──────────────────────────────────────────────────────────

    def _parse(self, text: str) -> None:
        for line in text.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                name, _, uid_s, gid_s, gecos, home, shell = parts[:7]
                self._users[name] = _UserEntry(
                    uid=int(uid_s), gid=int(gid_s),
                    gecos=gecos, home=home, shell=shell,
                )

    # ── queries ──────────────────────────────────────────────────────────

    def get(self, name: str) -> _UserEntry | None:
        return self._users.get(name)

    def uid(self, name: str) -> int | None:
        u = self._users.get(name)
        return u.uid if u else None

    def name_by_uid(self, uid: int) -> str | None:
        for name, u in self._users.items():
            if u.uid == uid:
                return name
        return None

    def all_names(self) -> list[str]:
        return list(self._users.keys())

    def next_uid(self) -> int:
        return max((u.uid for u in self._users.values()), default=1000) + 1

    # ── mutations ────────────────────────────────────────────────────────

    def add(self, name: str, *, uid: int | None = None, gid: int | None = None,
            home: str | None = None, shell: str = "/bin/bash") -> bool:
        if name in self._users:
            return False
        uid = uid or self.next_uid()
        gid = gid if gid is not None else uid
        home = home or f"/home/{name}"
        self._users[name] = _UserEntry(uid=uid, gid=gid, gecos=name, home=home, shell=shell)
        return True

    def remove(self, name: str) -> bool:
        return self._users.pop(name, None) is not None

    # ── passwd generation ────────────────────────────────────────────────

    def passwd_line(self, name: str) -> str:
        u = self._users[name]
        return f"{name}:x:{u.uid}:{u.gid}:{u.gecos}:{u.home}:{u.shell}"

    def passwd_text(self) -> str:
        return "\n".join(self.passwd_line(n) for n in self._users) + "\n"


class GroupDatabase:
    def __init__(self) -> None:
        self._groups: dict[str, _GroupEntry] = {}
        self._parse(_GROUP_HEADER)

    def _parse(self, text: str) -> None:
        for line in text.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                name, _, gid_s, members_s = parts[:4]
                members = [m for m in members_s.split(",") if m]
                self._groups[name] = _GroupEntry(gid=int(gid_s), members=members)

    def get(self, name: str) -> _GroupEntry | None:
        return self._groups.get(name)

    def gid(self, name: str) -> int | None:
        g = self._groups.get(name)
        return g.gid if g else None

    def next_gid(self) -> int:
        return max((g.gid for g in self._groups.values()), default=1000) + 1

    def add(self, name: str, *, gid: int | None = None) -> bool:
        if name in self._groups:
            return False
        self._groups[name] = _GroupEntry(gid=gid or self.next_gid(), members=[])
        return True

    def remove(self, name: str) -> bool:
        return self._groups.pop(name, None) is not None

    def group_line(self, name: str) -> str:
        g = self._groups[name]
        return f"{name}:x:{g.gid}:{','.join(g.members)}"

    def group_text(self) -> str:
        return "\n".join(self.group_line(n) for n in self._groups) + "\n"


# ── Virtual filesystem ──────────────────────────────────────────────────────


class FakeFilesystem:
    """In-memory Linux filesystem with full inode metadata.

    Directories are Inodes with ``is_dir=True``; files have ``is_dir=False``
    and store their text in ``content``.
    """

    def __init__(self, *, users: UserDatabase | None = None,
                 groups: GroupDatabase | None = None) -> None:
        self._users = users or UserDatabase()
        self._groups = groups or GroupDatabase()
        self._ino = 0
        self._root = self._make_dir(0o755)
        self._init_tree()

    # ── helpers ──────────────────────────────────────────────────────────

    def _make_dir(self, mode: int = 0o755, uid: int = 0, gid: int = 0,
                  mtime: datetime | None = None) -> Inode:
        self._ino += 1
        t = mtime or _BOOT
        return Inode(is_dir=True, mode=mode, uid=uid, gid=gid, children={}, mtime=t, ctime=t)

    def _make_file(self, content: str = "", mode: int = 0o644, uid: int = 0,
                   gid: int = 0, mtime: datetime | None = None) -> Inode:
        self._ino += 1
        t = mtime or _BOOT
        return Inode(is_dir=False, mode=mode, uid=uid, gid=gid, content=content, mtime=t, ctime=t)

    def _split(self, path: str) -> list[str]:
        return [p for p in path.split("/") if p]

    def _resolve(self, path: str) -> Inode | None:
        parts = self._split(path)
        node = self._root
        for p in parts:
            if not node.is_dir:
                return None
            if p == "..":
                return None
            if p not in node.children:
                return None
            node = node.children[p]
        return node

    def _parent(self, path: str) -> tuple[Inode, str] | None:
        parts = self._split(path)
        if not parts:
            return None
        parent = self._root
        for p in parts[:-1]:
            if not parent.is_dir or p not in parent.children:
                return None
            parent = parent.children[p]
        return parent, parts[-1]

    # ── initial tree ─────────────────────────────────────────────────────

    def _init_tree(self) -> None:
        r = self._root
        now = _BOOT

        def d(name: str, parent: Inode, **kw: object) -> Inode:
            n = self._make_dir(**{k: v for k, v in kw.items() if v is not None})
            parent.children[name] = n
            return n

        def f(name: str, parent: Inode, content: str = "", **kw: object) -> Inode:
            n = self._make_file(content, **{k: v for k, v in kw.items() if v is not None})
            parent.children[name] = n
            return n

        # ── /etc ──
        etc = d("etc", r)
        f("passwd", etc, self._users.passwd_text(), mode=0o644)
        f("shadow", etc, _SHADOW_HEADER, mode=0o640)
        f("group", etc, self._groups.group_text(), mode=0o644)
        f("hostname", etc, "honeypot\n")
        f("hosts", etc, "127.0.0.1 localhost\n127.0.1.1 honeypot\n")
        f("os-release", etc,
          'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\n'
          'VERSION_ID="22.0"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
          "VERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n")
        ssh = d("ssh", etc)
        f("sshd_config", ssh,
          "#Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
          "PubkeyAuthentication yes\nUsePAM yes\n")
        f("crontab", etc,
          "# /etc/crontab: system-wide crontab\n"
          "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
          "25 6    * * *   root    test -x /usr/sbin/anacron "
          "|| ( cd / && run-parts --report /etc/cron.daily )\n")

        # ── /var ──
        var = d("var", r)
        www = d("www", var)
        html = d("html", www)
        f("index.html", html, "<html><body>It works!</body></html>")
        log = d("log", var)
        f("auth.log", log,
          "Sep  8 10:42:13 honeypot sshd[1234]: Accepted password for root "
          "from 192.168.1.100 port 51234 ssh2\n"
          "Sep  8 10:47:55 honeypot sshd[1402]: Failed password for invalid "
          "user admin from 10.0.0.7 port 44112 ssh2\n")
        f("syslog", log,
          "Sep  8 10:42:11 honeypot systemd[1]: Started SSH Socket.\n"
          "Sep  8 10:42:13 honeypot systemd[1]: Started OpenSSH Server Daemon.\n")
        f("dmesg", log,
          "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-106) "
          "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0)\n")

        # ── /home ──
        home = d("home", r)
        admin = d("admin", home, uid=1001, gid=1001)
        f("notes.txt", admin, "password123\n", uid=1001, gid=1001)
        f(".bashrc", admin, "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
          uid=1001, gid=1001)
        user = d("user", home, uid=1002, gid=1002)
        f(".bashrc", user, "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
          uid=1002, gid=1002)
        antony = d("antony", home, uid=1000, gid=1000)
        f(".bash_history", antony, "ls -la\ncd /var/www\ncat /etc/passwd\n",
          uid=1000, gid=1000)
        f(".bashrc", antony, "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
          uid=1000, gid=1000)
        ssh_a = d(".ssh", antony, mode=0o700, uid=1000, gid=1000)
        f("authorized_keys", ssh_a,
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3FakeHoneypotKeyOnly antony@kali\n",
          mode=0o600, uid=1000, gid=1000)

        # ── /tmp ──
        tmp = d("tmp", r, mode=0o1777)
        d(".X11-unix", tmp)
        d("systemd-private-8d3f1a2b-nginx.service-abc", tmp)
        f("temp_install.log", tmp, "2026-09-08 10:42:13 installer started\n")

        # ── /bin, /sbin ──
        bin_d = d("bin", r)
        for name in (
            "bash", "cat", "ls", "less", "vi", "vim", "grep", "egrep", "fgrep",
            "awk", "sed", "head", "tail", "sort", "uniq", "wc", "cut", "find",
            "file", "touch", "mkdir", "rm", "tee", "dd", "chmod", "chown", "ln",
            "rmdir", "which", "stat", "strings", "base64", "openssl", "nc", "ncat",
            "ping", "wget", "curl", "ssh", "scp", "sftp", "kubectl", "ddrescue",
            "rsync", "rsyncd", "bash-completion", "sshd", "systemd-sysusers",
            "tmpfiles.d",
        ):
            f(name, bin_d, f"fake {name} stub\n", mode=0o755)

        sbin_d = d("sbin", r)
        for name in (
            "systemctl", "service", "journalctl", "coredumpctl", "ip", "route",
            "ss", "netstat", "lsof", "ifconfig", "arp", "find", "file", "stat",
            "mount", "chmod", "chown", "ln", "rmdir", "which", "strings", "base64",
            "openssl", "nc", "ncat", "ping", "wget", "curl", "ssh", "scp", "sftp",
            "kubectl", "ddrescue", "rsync", "rsyncd", "bash-completion",
        ):
            f(name, sbin_d, f"fake {name} stub\n", mode=0o755)

        # ── remaining top-level dirs ──
        for name in ("lib", "lib64", "boot", "dev", "opt", "srv", "mnt", "media", "sys"):
            d(name, r)
        usr = d("usr", r)
        d("bin", usr)
        d("lib", usr)
        d("local", usr)
        run = d("run", r)
        d("sshd", run)
        proc = d("proc", r)
        f("version", proc,
          "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-106) "
          "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld "
          "(GNU Binutils for Ubuntu) 2.38) "
          "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024\n")

        # ── /root ──
        root = d("root", r, mode=0o700)
        f("flag.txt", root, "flag{you_got_pwned}\n", uid=0, gid=0)
        f("README", root, "Do not delete this file.\n", uid=0, gid=0)
        f(".bashrc", root,
          "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
          "# If not running interactively, don't do anything\n"
          "case $- in\n    *i*) ;;\n      *) return;;\nesac\n",
          uid=0, gid=0)
        f(".profile", root,
          "# ~/.profile: executed by the command interpreter for login shells.\n",
          uid=0, gid=0)
        f(".bash_history", root,
          "ls -la\ncd /tmp\nwget http://192.168.1.100/payload.sh\nhistory\n",
          uid=0, gid=0)
        ssh_r = d(".ssh", root, mode=0o700, uid=0, gid=0)
        f("authorized_keys", ssh_r,
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FakeHoneypotKeyOnly root@honeypot\n",
          mode=0o600, uid=0, gid=0)

    # ── read-only queries ────────────────────────────────────────────────

    def exists(self, path: str) -> bool:
        return self._resolve(path) is not None

    def is_dir(self, path: str) -> bool:
        n = self._resolve(path)
        return n is not None and n.is_dir

    def is_file(self, path: str) -> bool:
        n = self._resolve(path)
        return n is not None and not n.is_dir

    def ls(self, path: str) -> list[str]:
        n = self._resolve(path)
        if n and n.is_dir:
            return sorted(n.children.keys())
        return []

    def cat(self, path: str) -> str:
        n = self._resolve(path)
        if n is None:
            return f"cat: {path}: No such file or directory"
        if n.is_dir:
            return f"cat: {path}: Is a directory"
        return n.content

    def cat_inode(self, path: str) -> Inode | None:
        n = self._resolve(path)
        if n is not None and not n.is_dir:
            return n
        return None

    def read_content(self, path: str) -> str | None:
        n = self._resolve(path)
        if n is None or n.is_dir:
            return None
        return n.content

    def file(self, path: str) -> str:
        n = self._resolve(path)
        if n is None:
            return f"{path}: cannot open ({path}: No such file or directory)\n"
        if n.is_dir:
            return f"{path}: directory\n"
        return f"{path}: ASCII text\n"

    def stat(self, path: str) -> str:
        n = self._resolve(path)
        if n is None:
            return f"stat: cannot stat '{path}': No such file or directory"
        sz = len(n.content.encode()) if not n.is_dir else 4096
        mode_str = _fmt_mode(n.mode, n.is_dir)
        uname = self._users.name_by_uid(n.uid) or str(n.uid)
        gname = self._group_name(n.gid) or str(n.gid)
        ts = n.mtime.strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"  File: {path}\n"
            f"  Size: {sz:<20}Blocks: 8          IO Block: 4096   "
            f"{'directory' if n.is_dir else 'regular file'}\n"
            f"  Access: ({oct(n.mode)[2:]}/{mode_str})  "
            f"Uid: ({n.uid:>5}/{uname:>8})   Gid: ({n.gid:>5}/{gname:>8})\n"
            f"Access: {ts}.000000000 +0000\n"
            f"Modify: {ts}.000000000 +0000\n"
            f"Change: {ts}.000000000 +0000\n"
            f" Birth: -\n"
        )

    def ls_long(self, path: str) -> str:
        entries = self.ls(path)
        if not entries:
            return ""
        lines = [f"total {len(entries)}"]
        for name in entries:
            child = self._resolve(f"{path.rstrip('/')}/{name}")
            if child is None:
                continue
            uname = self._users.name_by_uid(child.uid) or str(child.uid)
            gname = self._group_name(child.gid) or str(child.gid)
            sz = len(child.content.encode()) if not child.is_dir else 4096
            ts = child.mtime.strftime("%b %d %H:%M")
            mode_str = _fmt_mode(child.mode, child.is_dir)
            lines.append(
                f"{mode_str} 1 {uname:>8} {gname:>8} {sz:>6} {ts} {name}"
            )
        return "\n".join(lines) + "\n"

    def ls_long_single(self, path: str) -> str:
        n = self._resolve(path)
        if n is None:
            return f"ls: cannot access '{path}': No such file or directory"
        name = path.rsplit("/", 1)[-1] or path
        uname = self._users.name_by_uid(n.uid) or str(n.uid)
        gname = self._group_name(n.gid) or str(n.gid)
        sz = len(n.content.encode()) if not n.is_dir else 4096
        ts = n.mtime.strftime("%b %d %H:%M")
        mode_str = _fmt_mode(n.mode, n.is_dir)
        return f"{mode_str} 1 {uname:>8} {gname:>8} {sz:>6} {ts} {name}"

    def _group_name(self, gid: int) -> str | None:
        for name, g in self._groups._groups.items():
            if g.gid == gid:
                return name
        return None

    # ── mutations ────────────────────────────────────────────────────────

    def mkdir(self, path: str, *, mode: int = 0o755) -> bool:
        n = self._make_dir(mode=mode)
        return self._link(path, n)

    def touch(self, path: str, *, mode: int = 0o644) -> bool:
        existing = self._resolve(path)
        if existing is not None:
            if not existing.is_dir:
                existing.mtime = _now()
                return True
            return False
        return self._link(path, self._make_file("", mode=mode, mtime=_now()))

    def write_file(self, path: str, content: str, *, append: bool = False,
                   mode: int = 0o644) -> bool:
        existing = self._resolve(path)
        if existing is not None:
            if existing.is_dir:
                return False
            if append:
                existing.content += content
            else:
                existing.content = content
            existing.mtime = _now()
            return True
        return self._link(path, self._make_file(content, mode=mode, mtime=_now()))

    def rm(self, path: str) -> bool:
        n = self._resolve(path)
        if n is None:
            return False
        if n.is_dir:
            return False
        return self._unlink(path)

    def rmdir(self, path: str) -> bool:
        n = self._resolve(path)
        if n is None or not n.is_dir:
            return False
        if n.children:
            return False
        return self._unlink(path)

    def chmod(self, path: str, mode: int) -> bool:
        n = self._resolve(path)
        if n is None:
            return False
        n.mode = mode
        n.ctime = _now()
        return True

    def chown(self, path: str, uid: int | None = None, gid: int | None = None) -> bool:
        n = self._resolve(path)
        if n is None:
            return False
        if uid is not None:
            n.uid = uid
        if gid is not None:
            n.gid = gid
        n.ctime = _now()
        return True

    def cp(self, src: str, dst: str) -> bool:
        s = self._resolve(src)
        if s is None or s.is_dir:
            return False
        d_inode = self._resolve(dst)
        if d_inode is not None and d_inode.is_dir:
            dst = dst.rstrip("/") + "/" + src.rsplit("/", 1)[-1]
        return self._link(dst, self._make_file(
            s.content, mode=s.mode, uid=s.uid, gid=s.gid))

    def mv(self, src: str, dst: str) -> bool:
        s = self._resolve(src)
        if s is None:
            return False
        d_inode = self._resolve(dst)
        if d_inode is not None and d_inode.is_dir:
            dst = dst.rstrip("/") + "/" + src.rsplit("/", 1)[-1]
        if not self._unlink(src):
            return False
        return self._link(dst, s)

    # ── link / unlink internals ──────────────────────────────────────────

    def _link(self, path: str, inode: Inode) -> bool:
        parent, name = self._parent(path)
        if parent is None or not parent.is_dir:
            return False
        parent.children[name] = inode
        parent.mtime = _now()
        return True

    def _unlink(self, path: str) -> bool:
        parent, name = self._parent(path)
        if parent is None or not parent.is_dir:
            return False
        if name not in parent.children:
            return False
        del parent.children[name]
        parent.mtime = _now()
        return True

    # ── backward-compatible write() used by response_engine redirections ──

    def write(self, path: str, content: str, append: bool = False) -> bool:
        return self.write_file(path, content, append=append)

    # ── user / group helpers exposed to response engine ──────────────────

    @property
    def users(self) -> UserDatabase:
        return self._users

    @property
    def groups(self) -> GroupDatabase:
        return self._groups

    def refresh_etc(self) -> None:
        """Regenerate /etc/passwd and /etc/group after user/group changes."""
        pw = self._resolve("/etc/passwd")
        if pw and not pw.is_dir:
            pw.content = self._users.passwd_text()
        gr = self._resolve("/etc/group")
        if gr and not gr.is_dir:
            gr.content = self._groups.group_text()


# ── formatting helpers ──────────────────────────────────────────────────────


def _fmt_mode(mode: int, is_dir: bool) -> str:
    """``-rwxr-xr-x`` style string from an octal int."""
    bits = [
        "r" if mode & 0o400 else "-",
        "w" if mode & 0o200 else "-",
        "x" if mode & 0o100 else "-",
        "r" if mode & 0o040 else "-",
        "w" if mode & 0o020 else "-",
        "x" if mode & 0o010 else "-",
        "r" if mode & 0o004 else "-",
        "w" if mode & 0o002 else "-",
        "x" if mode & 0o001 else "-",
    ]
    kind = "d" if is_dir else "-" if not (mode & 0o170000 == 0o120000) else "l"
    return kind + "".join(bits)


def _now() -> datetime:
    return datetime.now(timezone.utc)
