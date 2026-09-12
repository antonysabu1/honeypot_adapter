import os
from dataclasses import dataclass
from datetime import datetime, timezone

from shared.filesystem import FakeFilesystem


@dataclass
class ResponsePlan:
    response_type: str
    content: str
    status: str


def _fake_date() -> str:
    """GNU `date`-style output (UTC, like a server misconfigured for realism)."""
    now = datetime.now(timezone.utc)
    return f"{now:%a %b} {now.day:2d} {now:%H:%M:%S} UTC {now:%Y}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def decide_response(
    protocol: str,
    session_id: str,
    action: str,
    parameters: dict,
    fs: FakeFilesystem,
    username: str = "root",
) -> ResponsePlan:
    cmd = action.strip()
    args = parameters.get("args", [])
    cwd = parameters.get("cwd", "/")
    base = cmd.split()[0] if cmd else ""

    # ls (exact base so lscpu/lsblk/lsof fall through to their handlers)
    if base == "ls":
        path_args = [a for a in args if not a.startswith("-")]
        show_all = any("a" in a for a in args if a.startswith("-"))
        path = _resolve_path(path_args[0], cwd) if path_args else cwd
        contents = fs.ls(path) or []
        if not show_all:
            contents = [c for c in contents if not c.startswith(".")]
        content_str = "\n".join(contents) if contents else ""
        return ResponsePlan("directory_listing", content_str, "0")

    # cat (handles cwd-relative paths passed by shells)
    if cmd.startswith("cat "):
        p = _resolve_path(args[0], cwd) if args else _resolve_path(cmd[4:].strip(), cwd)
        return ResponsePlan("file_contents", fs.cat(p), "0")

    if cmd == "pwd":
        return ResponsePlan("command_output", cwd, "0")

    if cmd == "whoami":
        return ResponsePlan("command_output", username or "root", "0")

    if cmd == "uname" or cmd.startswith("uname "):
        return ResponsePlan(
            "command_output",
            "Linux honeypot 5.15.0-105-generic "
            "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
            "0",
        )

    if cmd == "cd" or cmd.startswith("cd "):
        return ResponsePlan("command_output", "", "0")

    if cmd == "exit":
        return ResponsePlan("session_end", "logout", "0")

    if base == "echo":
        return ResponsePlan("command_output", cmd[5:].strip(), "0")

    if base == "id":
        return ResponsePlan("command_output", "uid=0(root) gid=0(root) groups=0(root)", "0")

    if base == "date":
        fmt = None
        for a in args:
            if a.startswith("+"):
                fmt = a[1:]
        if fmt:
            return ResponsePlan("command_output", _now().strftime(fmt) + "\n", "0")
        return ResponsePlan("command_output", _fake_date(), "0")

    if base == "ps":
        return ResponsePlan(
            "command_output",
            "PID TTY          TIME CMD\n"
            "    1 ?        00:00:01 systemd\n"
            "  782 ?        00:00:00 sshd\n"
            "  812 ?        00:00:00 sshd: root@pts/0\n"
            "  813 pts/0    00:00:00 bash",
            "0",
        )

    if base == "df":
        return ResponsePlan(
            "command_output",
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "udev             8193052       0   8193052   0% /dev\n"
            "/dev/sda1      20511312 5123456  14287856  27% /\n"
            "tmpfs             164228     172    164056   1% /run",
            "0",
        )

    if base == "hostname":
        return ResponsePlan("command_output", "honeypot", "0")

    if base in ("apt", "apt-get"):
        return ResponsePlan(
            "command_output",
            "Reading package lists... Done\n"
            "Building dependency tree... Done\n"
            "Reading state information... Done",
            "0",
        )

    if base == "uptime":
        return ResponsePlan(
            "command_output",
            f"{_fake_date()} up 2 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05",
            "0",
        )

    if base == "who":
        return ResponsePlan(
            "command_output",
            "root     pts/0        192.168.1.100    Mon Sep  8 10:42   still logged in\n"
            "\n"
            "wtmp begins Mon Sep  8 10:42:00 2026",
            "0",
        )

    if base == "last":
        return ResponsePlan(
            "command_output",
            "root     pts/0        192.168.1.100    Mon Sep  8 10:42   still logged in\n"
            "root     pts/0        10.0.0.7         Sun Sep  7 22:15 - 22:41  (00:26)\n"
            "reboot   system boot  5.15.0-105-generic Sun Sep  7 21:58   still running\n"
            "\nwtmp begins Sun Sep  7 21:58:00 2026",
            "0",
        )

    if base == "w":
        return ResponsePlan(
            "command_output",
            f"{_fake_date()} up 2 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "root     pts/0    192.168.1.100    10:42    0.00s  0.02s  0.00s -bash",
            "0",
        )

    if base == "nl":
        return ResponsePlan("command_output", "", "0")

    if base == "yes":
        out = args[0] if args else "y"
        return ResponsePlan("command_output", out + "\n", "0")

    if base == "seq":
        try:
            av = args[0] if args else None
            if av is None:
                return ResponsePlan("command_not_found", "seq: missing operand\n", "127")
            a = int(av)
            step = 1
            if len(args) == 1:
                # seq LAST
                b = a
                a = 1
            elif len(args) == 2:
                # seq FIRST LAST
                b = int(args[1])
            else:
                # seq FIRST INCREMENT LAST
                step = int(args[1])
                b = int(args[2])
            seq = list(range(a, b + 1, step))
            return ResponsePlan("command_output", "\n".join(map(str, seq)) + "\n", "0")
        except (ValueError, IndexError):
            return ResponsePlan("command_not_found", "seq: invalid numeric argument\n", "127")

    if base == "awk":
        return ResponsePlan("command_output", "", "0")

    if base == "basename":
        p = args[0] if args else ""
        return ResponsePlan("command_output", _base(p) + "\n", "0")

    if base == "dirname":
        p = args[0] if args else "."
        return ResponsePlan("command_output", _dir(p) + "\n", "0")

    if base == "touch":
        return ResponsePlan("command_output", "", "0")

    if base == "mkdir":
        return ResponsePlan("command_output", "", "0")

    if base == "rm":
        return ResponsePlan("command_output", "", "0")

    if base == "tee":
        return ResponsePlan("command_not_found", "tee: missing file operand\n", "127")

    if base == "cal":
        return ResponsePlan("command_output", "", "0")

    if base == "uname":
        return ResponsePlan(
            "command_output",
            "Linux honeypot 5.15.0-105-generic "
            "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
            "0",
        )

    if base == "head":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "head: missing file operand\n", "127")
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        n = _take_num(args, 10)
        lines = lines[:n]
        return ResponsePlan("command_output", "\n".join(lines) + "\n", "0")

    if base == "tail":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "tail: missing file operand\n", "127")
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        n = _take_num(args, 10)
        lines = lines[-n:] if n else lines
        return ResponsePlan("command_output", "\n".join(lines) + "\n", "0")

    if base == "sort":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "sort: missing file operand\n", "127")
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        return ResponsePlan("command_output", "\n".join(sorted(lines)) + "\n", "0")

    if base == "uniq":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "uniq: missing file operand\n", "127")
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        out = []
        for line in lines:
            if not out or line != out[-1]:
                out.append(line)
        return ResponsePlan("command_output", "\n".join(out) + "\n", "0")

    if base == "wc":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "wc: missing file operand\n", "127")
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        nlines = len(lines)
        nbytes = len(data.encode("utf-8"))
        return ResponsePlan("command_output", f"{nlines} {nbytes} {p}\n", "0")

    if base == "cut":
        p = _first_file(args, only_flag=True, cwd=cwd)
        if p is None:
            return ResponsePlan("command_not_found", "cut: missing file operand\n", "127")
        delim = " "
        fields = "1"
        for a in args:
            if a.startswith("-d") and len(a) > 2:
                delim = a[2:]
            elif a == "-d":
                delim = args[args.index(a) + 1]
            if a.startswith("-f") and len(a) > 2:
                fields = a[2:]
            elif a == "-f":
                fields = args[args.index(a) + 1]
        data = fs.cat(p)
        lines = data.splitlines() if data else []
        idxs = [int(x) - 1 for x in fields.split(",")]
        out_lines = [
            ":".join((parts[i] if i < len(parts) else "") for i in idxs)
            for parts in (line.split(delim) for line in lines)
        ]
        return ResponsePlan("command_output", "\n".join(out_lines) + "\n", "0")

    if base == "dd":
        return ResponsePlan("command_output", "0+1 records in\n0+1 records out\n", "0")

    if base == "du":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "du: missing file operand\n", "127")
        nbytes = len(fs.cat(p).encode("utf-8")) or 4096
        return ResponsePlan("command_output", f"{nbytes}\t{p}\n", "0")

    if base == "lscpu":
        return ResponsePlan(
            "command_output",
            "Architecture:         x86_64\n"
            "CPU op-mode(s):       32-bit, 64-bit\n"
            "Byte Order:           Little Endian\n"
            "CPU(s):               1\n"
            "Thread(s) per core:   1\n"
            "Core(s) per socket:   1\n"
            "Socket(s):            1\n"
            "Vendor ID:            GenuineIntel\n"
            "CPU family:           6\n"
            "Model:                140\n"
            "Model name:           Intel(R) Core(TM) i7-10875H CPU @ 2.30GHz\n"
            "Stepping:             1\n"
            "CPU MHz:              2294.000\n"
            "BogoMIPS:             4647.00\n"
            "Virtualization:       VT-x\n"
            "L1d cache:            32K\n"
            "L1i cache:            32K\n"
            "L2 cache:             4096K\n"
            "L3 cache:             12288K\n",
            "0",
        )

    if base == "lsblk":
        return ResponsePlan(
            "command_output",
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\n"
            "sda      8:0    0    64G  0 disk \n"
            "sda1     8:1    0    64G  0 part /\n"
            "sr0     11:0    1  1024M  0 rom  \n",
            "0",
        )

    if base == "ss":
        return ResponsePlan(
            "command_output",
            "Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process\n"
            "tcp    LISTEN  0       128         0.0.0.0:22          0.0.0.0:*\n"
            "tcp    LISTEN  0       128            [::]:22             [::]:*\n"
            "tcp    ESTAB  0       0      10.0.2.15:22          192.168.1.100:51234\n"
            "tcp    LISTEN  0       128         127.0.0.1:631         0.0.0.0:*\n",
            "0",
        )

    if base == "netstat":
        return ResponsePlan(
            "command_output",
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN\n"
            "tcp6       0      0 :::22                   :::*                    LISTEN\n",
            "0",
        )

    if base == "lsof":
        return ResponsePlan(
            "command_output",
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "sshd      782 root    3u  IPv4  19457      0t0  TCP *:22 (LISTEN)\n"
            "sshd      812 root    3u  IPv4  19712      0t0  TCP *:22 (LISTEN)\n"
            "sshd      813 root    3u  IPv4  19713      0t0  TCP 10.0.2.15:22->192.168.1.100:51234 (ESTABLISHED)\n",
            "0",
        )

    if base == "ifconfig":
        return ResponsePlan(
            "command_output",
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
            "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0",
            "0",
        )

    if base == "arp":
        return ResponsePlan(
            "command_output",
            "Address                  HWtype  HWaddress           Flags Mask Iface\n"
            "gateway                 ether   52:54:00:12:34:56   C                     eth0\n"
            "10.10.10.1              ether   52:54:00:c0:ff:ee   C                     eth0\n"
            "10.10.10.50             ether   52:54:00:ff:ee:00   C                     eth0\n"
            "10.10.10.100            ether   52:54:00:ff:ee:01   C                     eth0\n"
            "10.10.10.150            ether   52:54:00:ff:ee:02   C                     eth0\n"
            "10.10.10.200            ether   52:54:00:ff:ee:03   C                     eth0\n",
            "0",
        )

    if base == "find":
        name = None
        start = cwd
        start_given = False
        for i, a in enumerate(args):
            if a in ("-name", "-iname") and i + 1 < len(args):
                name = args[i + 1].strip('"').strip("'")
            elif not a.startswith("-") and not start_given:
                start = a
                start_given = True
        results = []
        if name:
            dirs_to_search = [start] if fs.is_dir(start) else []
            for d in ["/root", "/home/admin", "/home/antony"]:
                if d != start and fs.is_dir(d):
                    dirs_to_search.append(d)
            for d in dirs_to_search:
                if fs.ls(d):
                    for f in fs.ls(d):
                        if f == name:
                            results.append(f"{d}/{f}")
        return ResponsePlan("command_output", "\n".join(results) + "\n", "0")

    if base == "file":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "file: missing operand\n", "127")
        node = fs._resolve(p)
        if isinstance(node, dict):
            return ResponsePlan("command_output", f"{p}: directory\n", "0")
        return ResponsePlan(
            "command_output",
            f"{p}: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), "
            "statically linked, for GNU/Linux 3.2.0, not stripped\n",
            "0",
        )

    if base == "stat":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "stat: missing file operand\n", "127")
        return ResponsePlan(
            "command_output",
            f"  File: {p}\n"
            "  Size: 4096\t\tBlocks: 8\t\tIO Block: 4096\n"
            "  Device: 20357h/132109d\n"
            "  Inode: 12856505\n"
            "  Links: 1\n"
            "  Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n"
            "  Access: 2026-09-08 12:00:01.000000000 +0000\n"
            "  Modify: 2026-09-08 10:42:13.000000000 +0000\n"
            "  Change: 2026-09-08 10:42:13.000000000 +0000\n"
            "  Birth: 2026-09-08 10:42:13.000000000 +0000\n",
            "0",
        )

    if base == "mount":
        return ResponsePlan(
            "command_output",
            "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "udev on /dev type devtmpfs (rw,nosuid,relatime,size=587484k,nr_inodes=146871,mode=755)\n"
            "devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)\n"
            "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=121760k,mode=755)\n"
            "/dev/sda1 on / type ext4 (rw,relatime)\n"
            "securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
            "tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)\n"
            "cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)\n"
            "tmpfs on /run/user/0 type tmpfs (rw,nosuid,nodev,relatime,size=121760k,mode=700,uid=0,gid=0)\n",
            "0",
        )

    if base == "chmod":
        return ResponsePlan("command_output", "", "0")

    if base == "chown":
        return ResponsePlan("command_output", "", "0")

    if base == "ln":
        return ResponsePlan("command_output", "", "0")

    if base == "rmdir":
        return ResponsePlan("command_output", "", "0")

    if base == "realpath":
        p = args[0] if args else "."
        return ResponsePlan("command_output", os.path.normpath(p) + "\n", "0")

    if base == "type":
        p = args[0] if args else "bash"
        for c in (f"/usr/bin/{p}", f"/usr/sbin/{p}", f"/bin/{p}", f"/sbin/{p}"):
            if fs.exists(c):
                return ResponsePlan("command_output", f"{p} is /usr/bin/{p}\n", "0")
        return ResponsePlan("command_not_found", f"{p}: command not found\n", "127")

    if base == "which":
        p = args[0] if args else "bash"
        for c in (f"/usr/bin/{p}", f"/usr/sbin/{p}", f"/bin/{p}", f"/sbin/{p}"):
            if fs.exists(c):
                return ResponsePlan("command_output", c + "\n", "0")
        return ResponsePlan("command_not_found", f"{p}: command not found\n", "127")

    if base == "strings":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "strings: missing file operand\n", "127")
        return ResponsePlan("command_output", "ELF\n", "0")

    if base == "base64":
        p = _first_file(args, cwd)
        if p is None:
            return ResponsePlan("command_not_found", "base64: invalid option -- 'd'\n", "127")
        return ResponsePlan("command_output", "REPLACE_BASE64\n", "0")

    if base == "openssl":
        cmd_nonflag = [a for a in args if not a.startswith("-")]
        if cmd_nonflag and cmd_nonflag[0] == "rand":
            return ResponsePlan("command_output", "a1b2c3d4e5f60718\n", "0")
        return ResponsePlan("command_output", "Generating a 2048 bit RSA private key\n..\n+...", "0")

    if base == "systemctl":
        return ResponsePlan(
            "command_output",
            "\u25cf sshd.service - OpenBSD Secure Shell server\n"
            "     Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; preset: enabled)\n"
            "     Active: active (running)\n\n"
            "   Main PID: 782 (sshd)\n"
            "      Tasks: 1 (limit: 2303)\n"
            "     Memory: 4.0M\n"
            "        CPU: 1.234s\n"
            "     CGroup: /system.slice/sshd.service\n"
            "             \u2514\u2500\u2500 782 /usr/sbin/sshd -D\n",
            "0",
        )

    if base == "service":
        return ResponsePlan(
            "command_output",
            "\u25cf sshd.service - OpenBSD Secure Shell server\n"
            "     Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; preset: enabled)\n"
            "     Active: active (running)\n\n"
            "   Main PID: 782 (sshd)\n"
            "      Tasks: 1 (limit: 2303)\n"
            "     Memory: 4.0M\n"
            "        CPU: 1.234s\n"
            "     CGroup: /system.slice/sshd.service\n"
            "             \u2514\u2500\u2500 782 /usr/sbin/sshd -D\n",
            "0",
        )

    if base == "journalctl":
        return ResponsePlan(
            "command_output",
            f"-- Logs begin at Mon 2026-09-07 21:58:00 UTC, end at {_fake_date()} --\n"
            "Sep 08 10:42:11 honeypot systemd[1]: Started OpenBSD Secure Shell server.\n"
            "Sep 08 10:42:13 honeypot sshd[782]: Server listening on 0.0.0.0 port 22.\n"
            "Sep 08 10:42:13 honeypot sshd[782]: Server listening on :: port 22.\n"
            "Sep 08 10:42:18 honeypot sshd[1234]: Accepted password for root from 192.168.1.100 port 51234 ssh2\n",
            "0",
        )

    if base == "coredumpctl":
        return ResponsePlan(
            "command_output",
            "TEM  PID  UID  GID   AGE   RUNTIME   DESCRIPTION\n"
            "(empty)\n\n"
            "No coredumps found.\n",
            "0",
        )

    if base == "bash":
        return ResponsePlan("command_output", "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n", "0")

    if base == "python" or base == "python3":
        return ResponsePlan(
            "command_output",
            "Python 3.11.8 (main, Dec 15 2023, 12:00:00) [GCC 13.2.0] on linux\n"
            "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> ",
            "0",
        )

    if base in ("perl",):
        return ResponsePlan(
            "command_output",
            "Can't locate object method \"print\" via package \"leak test\" (perhaps you forgot to load \"leak test\"?) at -e line 1.\n",
            "0",
        )

    if base == "ruby":
        return ResponsePlan("command_output", "-:1: syntax error, unexpected end-of-input\n", "0")

    if base == "php":
        return ResponsePlan("command_output", "command not found\n", "127")

    if base in ("node", "go", "rust", "java", "cargo", "npm", "yarn", "pnpm", "gradle", "maven"):
        return ResponsePlan("command_not_found", f"{base}: command not found\n", "127")

    if base == "gcc" or base == "g++":
        return ResponsePlan("command_output", "gcc: fatal error: no input files\ncompilation terminated.\n", "127")

    if base == "make":
        return ResponsePlan("command_output", "make: *** No targets specified and no makefile found.  Stop.\n", "127")

    if base == "cmake":
        return ResponsePlan("command_not_found", "cmake: command not found\n", "127")

    if base == "pip" or base == "pip3":
        return ResponsePlan(
            "command_output",
            "Package    Version\n"
            "----------- -------\n"
            "pip        24.0\n"
            "setuptools 69.0.3\n",
            "0",
        )

    # wget/curl/nc/ncat/nmap intentionally kept as command_not_found in this step
    # (passive stubs for external-network tools come in Step 2, no outbound).
    if base == "wget" or base == "curl" or base == "nc" or base == "ncat" or base == "nmap":
        return ResponsePlan("command_not_found", f"bash: {base}: command not found\n", "127")

    if base == "history":
        return ResponsePlan("command_output", fs.cat("/root/.bash_history"), "0")

    if base == "ping":
        return ResponsePlan("command_output", "ping: icmp open socket: Operation not permitted\n", "127")

    if base == "ssh" or base == "scp" or base == "sftp" or base == "rsync":
        return ResponsePlan("command_not_found", f"bash: {base}: command not found\n", "127")

    return ResponsePlan("command_not_found", f"bash: {cmd}: command not found\n", "127")


def _base(p: str) -> str:
    return p.rsplit("/", 1)[-1] if "/" in p else p


def _dir(p: str) -> str:
    return "/".join(p.split("/")[:-1]) or "/"


def _resolve_path(path: str, cwd: str) -> str:
    if path.startswith("/"):
        return path
    return cwd.rstrip("/") + "/" + path


def _first_file(args: list, cwd: str = "/", only_flag: bool = False) -> str | None:
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-") or not a:
            # Flags that consume a following value (e.g. head -n 2 file)
            # should not let that value be mistaken for a path.
            if a in ("-n", "-d", "-f", "-c"):
                skip_next = True
            continue
        return _resolve_path(a, cwd)
    return None


def _take_num(args: list, default: int) -> int:
    for i, a in enumerate(args):
        if a.startswith("-n") and len(a) > 2:
            try:
                return int(a[2:])
            except ValueError:
                return default
        if a == "-n" and i + 1 < len(args):
            try:
                return int(args[i + 1])
            except ValueError:
                return default
    return default
