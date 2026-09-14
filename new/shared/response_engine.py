import os

from dataclasses import dataclass

from datetime import datetime, timezone

from shared.filesystem import FakeFilesystem
from shared.shell import resolve_cd
from shared.shell_syntax import (
    apply_filter,
    is_devnull,
    parse_segment,
    split_streams,
    visible_output,
)

@dataclass
class ResponsePlan:
    response_type: str
    content: str
    status: str
    # Where the line's output was routed, when it was redirected. Recorded as
    # intel by the transports instead of being shown to the attacker.
    redirect: str | None = None

def _fake_date() -> str:
    """GNU `date`-style output (UTC, like a server misconfigured for realism)."""
    now = datetime.now(timezone.utc)
    return f"{now:%a %b} {now.day:2d} {now:%H:%M:%S} UTC {now:%Y}"

def _now() -> datetime:
    return datetime.now(timezone.utc)

@dataclass
class _Ctx:
    """Everything one command handler is given (all read-only)."""

    cmd: str
    base: str
    args: list
    cwd: str
    fs: FakeFilesystem
    username: str

def _cmd_ls(ctx: _Ctx) -> ResponsePlan | None:
    # exact base, so lscpu/lsblk/lsof fall through to their own handlers
    if ctx.base == 'ls':
        path_args = [a for a in ctx.args if not a.startswith('-')]
        show_all = any(('a' in a for a in ctx.args if a.startswith('-')))
        path = _resolve_path(path_args[0], ctx.cwd) if path_args else ctx.cwd
        # bash complains instead of silently printing nothing, and exits 2.
        if not ctx.fs.exists(path):
            return ResponsePlan('command_not_found',
                                f"ls: cannot access '{path}': No such file or directory\n", '2')
        if ctx.fs.is_file(path):
            return ResponsePlan('directory_listing', path + '\n', '0')
        contents = ctx.fs.ls(path) or []
        if not show_all:
            contents = [c for c in contents if not c.startswith('.')]
        content_str = '\n'.join(contents) if contents else ''
        return ResponsePlan('directory_listing', content_str, '0')
    return None

def _cmd_cat(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd.startswith('cat '):
        p = _resolve_path(ctx.args[0], ctx.cwd) if ctx.args else _resolve_path(ctx.cmd[4:].strip(), ctx.cwd)
        # A missing file is a failure in bash, so `cat /nope && whoami` must not
        # run the second command. The message stays as it was.
        status = '0' if ctx.fs.is_file(p) else '1'
        return ResponsePlan('file_contents', ctx.fs.cat(p), status)
    return None

def _cmd_grep(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'grep':
        # The pattern is the first operand and the file the one after it.
        operands = [a for a in ctx.args if a and not a.startswith('-')]
        if len(operands) < 2:
            return ResponsePlan('command_not_found', 'grep: missing file operand\n', '127')
        p = _resolve_path(operands[1], ctx.cwd)
        if ctx.fs.is_dir(p):
            return ResponsePlan('command_not_found', f'grep: {p}: Is a directory\n', '2')
        if not ctx.fs.is_file(p):
            return ResponsePlan('command_not_found',
                                f'grep: {p}: No such file or directory\n', '2')
        # The same matcher the pipeline stage uses, so `grep x f` and
        # `cat f | grep x` can never disagree. Status 1 means "no match".
        filtered = apply_filter(ctx.cmd, ctx.fs.cat(p))
        if filtered is None:
            return ResponsePlan('command_not_found', 'grep: missing pattern\n', '2')
        return ResponsePlan('command_output', filtered[0], filtered[1])
    return None

def _cmd_pwd(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd == 'pwd':
        return ResponsePlan('command_output', ctx.cwd, '0')
    return None

def _cmd_whoami(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd == 'whoami':
        return ResponsePlan('command_output', ctx.username or 'root', '0')
    return None

def _cmd_uname(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd == 'uname' or ctx.cmd.startswith('uname '):
        return ResponsePlan('command_output', 'Linux honeypot 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux', '0')
    return None

def _cmd_cd(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd == 'cd' or ctx.cmd.startswith('cd '):
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_exit(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.cmd == 'exit':
        return ResponsePlan('session_end', 'logout', '0')
    return None

def _cmd_echo(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'echo':
        return ResponsePlan('command_output', ctx.cmd[5:].strip(), '0')
    return None

def _cmd_id(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'id':
        return ResponsePlan('command_output', 'uid=0(root) gid=0(root) groups=0(root)', '0')
    return None

def _cmd_date(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'date':
        fmt = None
        for a in ctx.args:
            if a.startswith('+'):
                fmt = a[1:]
        if fmt:
            return ResponsePlan('command_output', _now().strftime(fmt) + '\n', '0')
        return ResponsePlan('command_output', _fake_date(), '0')
    return None

def _cmd_ps(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ps':
        return ResponsePlan('command_output', 'PID TTY          TIME CMD\n    1 ?        00:00:01 systemd\n  782 ?        00:00:00 sshd\n  812 ?        00:00:00 sshd: root@pts/0\n  813 pts/0    00:00:00 bash', '0')
    return None

def _cmd_df(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'df':
        return ResponsePlan('command_output', 'Filesystem     1K-blocks    Used Available Use% Mounted on\nudev             8193052       0   8193052   0% /dev\n/dev/sda1      20511312 5123456  14287856  27% /\ntmpfs             164228     172    164056   1% /run', '0')
    return None

def _cmd_hostname(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'hostname':
        return ResponsePlan('command_output', 'honeypot', '0')
    return None

def _cmd_apt(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base in ('apt', 'apt-get'):
        return ResponsePlan('command_output', 'Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done', '0')
    return None

def _cmd_uptime(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'uptime':
        return ResponsePlan('command_output', f'{_fake_date()} up 2 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05', '0')
    return None

def _cmd_who(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'who':
        return ResponsePlan('command_output', 'root     pts/0        192.168.1.100    Mon Sep  8 10:42   still logged in\n\nwtmp begins Mon Sep  8 10:42:00 2026', '0')
    return None

def _cmd_last(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'last':
        return ResponsePlan('command_output', 'root     pts/0        192.168.1.100    Mon Sep  8 10:42   still logged in\nroot     pts/0        10.0.0.7         Sun Sep  7 22:15 - 22:41  (00:26)\nreboot   system boot  5.15.0-105-generic Sun Sep  7 21:58   still running\n\nwtmp begins Sun Sep  7 21:58:00 2026', '0')
    return None

def _cmd_w(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'w':
        return ResponsePlan('command_output', f'{_fake_date()} up 2 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.100    10:42    0.00s  0.02s  0.00s -bash', '0')
    return None

def _cmd_nl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'nl':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_yes(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'yes':
        out = ctx.args[0] if ctx.args else 'y'
        return ResponsePlan('command_output', out + '\n', '0')
    return None

def _cmd_seq(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'seq':
        try:
            av = ctx.args[0] if ctx.args else None
            if av is None:
                return ResponsePlan('command_not_found', 'seq: missing operand\n', '127')
            a = int(av)
            step = 1
            if len(ctx.args) == 1:
                b = a
                a = 1
            elif len(ctx.args) == 2:
                b = int(ctx.args[1])
            else:
                step = int(ctx.args[1])
                b = int(ctx.args[2])
            seq = list(range(a, b + 1, step))
            return ResponsePlan('command_output', '\n'.join(map(str, seq)) + '\n', '0')
        except (ValueError, IndexError):
            return ResponsePlan('command_not_found', 'seq: invalid numeric argument\n', '127')
    return None

def _cmd_awk(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'awk':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_basename(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'basename':
        p = ctx.args[0] if ctx.args else ''
        return ResponsePlan('command_output', _base(p) + '\n', '0')
    return None

def _cmd_dirname(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'dirname':
        p = ctx.args[0] if ctx.args else '.'
        return ResponsePlan('command_output', _dir(p) + '\n', '0')
    return None

def _cmd_touch(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'touch':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_mkdir(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'mkdir':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_rm(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'rm':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_tee(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'tee':
        return ResponsePlan('command_not_found', 'tee: missing file operand\n', '127')
    return None

def _cmd_cal(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'cal':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_uname_dup(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'uname':
        return ResponsePlan('command_output', 'Linux honeypot 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux', '0')
    return None

def _cmd_head(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'head':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'head: missing file operand\n', '127')
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        n = _take_num(ctx.args, 10)
        lines = lines[:n]
        return ResponsePlan('command_output', '\n'.join(lines) + '\n', '0')
    return None

def _cmd_tail(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'tail':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'tail: missing file operand\n', '127')
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        n = _take_num(ctx.args, 10)
        lines = lines[-n:] if n else lines
        return ResponsePlan('command_output', '\n'.join(lines) + '\n', '0')
    return None

def _cmd_sort(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'sort':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'sort: missing file operand\n', '127')
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        return ResponsePlan('command_output', '\n'.join(sorted(lines)) + '\n', '0')
    return None

def _cmd_uniq(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'uniq':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'uniq: missing file operand\n', '127')
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        out = []
        for line in lines:
            if not out or line != out[-1]:
                out.append(line)
        return ResponsePlan('command_output', '\n'.join(out) + '\n', '0')
    return None

def _cmd_wc(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'wc':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'wc: missing file operand\n', '127')
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        # bash prints the byte/word counts only when they were asked for.
        if '-l' in ctx.args:
            return ResponsePlan('command_output', f'{len(lines)} {p}\n', '0')
        nbytes = len(data.encode('utf-8'))
        return ResponsePlan('command_output', f'{len(lines)} {len(data.split())} {nbytes} {p}\n', '0')
    return None

def _cmd_cut(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'cut':
        p = _first_file(ctx.args, only_flag=True, cwd=ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'cut: missing file operand\n', '127')
        delim = ' '
        fields = '1'
        for a in ctx.args:
            if a.startswith('-d') and len(a) > 2:
                delim = a[2:]
            elif a == '-d':
                delim = ctx.args[ctx.args.index(a) + 1]
            if a.startswith('-f') and len(a) > 2:
                fields = a[2:]
            elif a == '-f':
                fields = ctx.args[ctx.args.index(a) + 1]
        data = ctx.fs.cat(p)
        lines = data.splitlines() if data else []
        idxs = [int(x) - 1 for x in fields.split(',')]
        out_lines = [':'.join((parts[i] if i < len(parts) else '' for i in idxs)) for parts in (line.split(delim) for line in lines)]
        return ResponsePlan('command_output', '\n'.join(out_lines) + '\n', '0')
    return None

def _cmd_dd(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'dd':
        return ResponsePlan('command_output', '0+1 records in\n0+1 records out\n', '0')
    return None

def _cmd_du(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'du':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'du: missing file operand\n', '127')
        nbytes = len(ctx.fs.cat(p).encode('utf-8')) or 4096
        return ResponsePlan('command_output', f'{nbytes}\t{p}\n', '0')
    return None

def _cmd_lscpu(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'lscpu':
        return ResponsePlan('command_output', 'Architecture:         x86_64\nCPU op-mode(s):       32-bit, 64-bit\nByte Order:           Little Endian\nCPU(s):               1\nThread(s) per core:   1\nCore(s) per socket:   1\nSocket(s):            1\nVendor ID:            GenuineIntel\nCPU family:           6\nModel:                140\nModel name:           Intel(R) Core(TM) i7-10875H CPU @ 2.30GHz\nStepping:             1\nCPU MHz:              2294.000\nBogoMIPS:             4647.00\nVirtualization:       VT-x\nL1d cache:            32K\nL1i cache:            32K\nL2 cache:             4096K\nL3 cache:             12288K\n', '0')
    return None

def _cmd_lsblk(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'lsblk':
        return ResponsePlan('command_output', 'NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\nsda      8:0    0    64G  0 disk \nsda1     8:1    0    64G  0 part /\nsr0     11:0    1  1024M  0 rom  \n', '0')
    return None

def _cmd_ss(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ss':
        return ResponsePlan('command_output', 'Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process\ntcp    LISTEN  0       128         0.0.0.0:22          0.0.0.0:*\ntcp    LISTEN  0       128            [::]:22             [::]:*\ntcp    ESTAB  0       0      10.0.2.15:22          192.168.1.100:51234\ntcp    LISTEN  0       128         127.0.0.1:631         0.0.0.0:*\n', '0')
    return None

def _cmd_netstat(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'netstat':
        return ResponsePlan('command_output', 'Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN\ntcp6       0      0 :::22                   :::*                    LISTEN\n', '0')
    return None

def _cmd_lsof(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'lsof':
        return ResponsePlan('command_output', 'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nsshd      782 root    3u  IPv4  19457      0t0  TCP *:22 (LISTEN)\nsshd      812 root    3u  IPv4  19712      0t0  TCP *:22 (LISTEN)\nsshd      813 root    3u  IPv4  19713      0t0  TCP 10.0.2.15:22->192.168.1.100:51234 (ESTABLISHED)\n', '0')
    return None

def _cmd_ifconfig(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ifconfig':
        return ResponsePlan('command_output', 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0', '0')
    return None

def _cmd_arp(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'arp':
        return ResponsePlan('command_output', 'Address                  HWtype  HWaddress           Flags Mask Iface\ngateway                 ether   52:54:00:12:34:56   C                     eth0\n10.10.10.1              ether   52:54:00:c0:ff:ee   C                     eth0\n10.10.10.50             ether   52:54:00:ff:ee:00   C                     eth0\n10.10.10.100            ether   52:54:00:ff:ee:01   C                     eth0\n10.10.10.150            ether   52:54:00:ff:ee:02   C                     eth0\n10.10.10.200            ether   52:54:00:ff:ee:03   C                     eth0\n', '0')
    return None

def _cmd_find(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'find':
        name = None
        start = ctx.cwd
        start_given = False
        for i, a in enumerate(ctx.args):
            if a in ('-name', '-iname') and i + 1 < len(ctx.args):
                name = ctx.args[i + 1].strip('"').strip("'")
            elif not a.startswith('-') and (not start_given):
                start = a
                start_given = True
        results = []
        if name:
            dirs_to_search = [start] if ctx.fs.is_dir(start) else []
            for d in ['/root', '/home/admin', '/home/antony']:
                if d != start and ctx.fs.is_dir(d):
                    dirs_to_search.append(d)
            for d in dirs_to_search:
                if ctx.fs.ls(d):
                    for f in ctx.fs.ls(d):
                        if f == name:
                            results.append(f'{d}/{f}')
        return ResponsePlan('command_output', '\n'.join(results) + '\n', '0')
    return None

def _cmd_file(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'file':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'file: missing operand\n', '127')
        node = ctx.fs._resolve(p)
        if isinstance(node, dict):
            return ResponsePlan('command_output', f'{p}: directory\n', '0')
        return ResponsePlan('command_output', f'{p}: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, not stripped\n', '0')
    return None

def _cmd_stat(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'stat':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'stat: missing file operand\n', '127')
        return ResponsePlan('command_output', f'  File: {p}\n  Size: 4096\t\tBlocks: 8\t\tIO Block: 4096\n  Device: 20357h/132109d\n  Inode: 12856505\n  Links: 1\n  Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n  Access: 2026-09-08 12:00:01.000000000 +0000\n  Modify: 2026-09-08 10:42:13.000000000 +0000\n  Change: 2026-09-08 10:42:13.000000000 +0000\n  Birth: 2026-09-08 10:42:13.000000000 +0000\n', '0')
    return None

def _cmd_mount(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'mount':
        return ResponsePlan('command_output', 'sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\nudev on /dev type devtmpfs (rw,nosuid,relatime,size=587484k,nr_inodes=146871,mode=755)\ndevpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)\ntmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=121760k,mode=755)\n/dev/sda1 on / type ext4 (rw,relatime)\nsecurityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\ntmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)\ncgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)\ntmpfs on /run/user/0 type tmpfs (rw,nosuid,nodev,relatime,size=121760k,mode=700,uid=0,gid=0)\n', '0')
    return None

def _cmd_chmod(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'chmod':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_chown(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'chown':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_ln(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ln':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_rmdir(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'rmdir':
        return ResponsePlan('command_output', '', '0')
    return None

def _cmd_realpath(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'realpath':
        p = ctx.args[0] if ctx.args else '.'
        return ResponsePlan('command_output', os.path.normpath(p) + '\n', '0')
    return None

def _cmd_type(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'type':
        p = ctx.args[0] if ctx.args else 'bash'
        for c in (f'/usr/bin/{p}', f'/usr/sbin/{p}', f'/bin/{p}', f'/sbin/{p}'):
            if ctx.fs.exists(c):
                return ResponsePlan('command_output', f'{p} is /usr/bin/{p}\n', '0')
        return ResponsePlan('command_not_found', f'{p}: command not found\n', '127')
    return None

def _cmd_which(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'which':
        p = ctx.args[0] if ctx.args else 'bash'
        for c in (f'/usr/bin/{p}', f'/usr/sbin/{p}', f'/bin/{p}', f'/sbin/{p}'):
            if ctx.fs.exists(c):
                return ResponsePlan('command_output', c + '\n', '0')
        return ResponsePlan('command_not_found', f'{p}: command not found\n', '127')
    return None

def _cmd_strings(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'strings':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', 'strings: missing file operand\n', '127')
        return ResponsePlan('command_output', 'ELF\n', '0')
    return None

def _cmd_base64(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'base64':
        p = _first_file(ctx.args, ctx.cwd)
        if p is None:
            return ResponsePlan('command_not_found', "base64: invalid option -- 'd'\n", '127')
        return ResponsePlan('command_output', 'REPLACE_BASE64\n', '0')
    return None

def _cmd_openssl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'openssl':
        cmd_nonflag = [a for a in ctx.args if not a.startswith('-')]
        if cmd_nonflag and cmd_nonflag[0] == 'rand':
            return ResponsePlan('command_output', 'a1b2c3d4e5f60718\n', '0')
        return ResponsePlan('command_output', 'Generating a 2048 bit RSA private key\n..\n+...', '0')
    return None

def _cmd_systemctl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'systemctl':
        return ResponsePlan('command_output', '● sshd.service - OpenBSD Secure Shell server\n     Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; preset: enabled)\n     Active: active (running)\n\n   Main PID: 782 (sshd)\n      Tasks: 1 (limit: 2303)\n     Memory: 4.0M\n        CPU: 1.234s\n     CGroup: /system.slice/sshd.service\n             └── 782 /usr/sbin/sshd -D\n', '0')
    return None

def _cmd_service(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'service':
        return ResponsePlan('command_output', '● sshd.service - OpenBSD Secure Shell server\n     Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; preset: enabled)\n     Active: active (running)\n\n   Main PID: 782 (sshd)\n      Tasks: 1 (limit: 2303)\n     Memory: 4.0M\n        CPU: 1.234s\n     CGroup: /system.slice/sshd.service\n             └── 782 /usr/sbin/sshd -D\n', '0')
    return None

def _cmd_journalctl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'journalctl':
        return ResponsePlan('command_output', f'-- Logs begin at Mon 2026-09-07 21:58:00 UTC, end at {_fake_date()} --\nSep 08 10:42:11 honeypot systemd[1]: Started OpenBSD Secure Shell server.\nSep 08 10:42:13 honeypot sshd[782]: Server listening on 0.0.0.0 port 22.\nSep 08 10:42:13 honeypot sshd[782]: Server listening on :: port 22.\nSep 08 10:42:18 honeypot sshd[1234]: Accepted password for root from 192.168.1.100 port 51234 ssh2\n', '0')
    return None

def _cmd_coredumpctl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'coredumpctl':
        return ResponsePlan('command_output', 'TEM  PID  UID  GID   AGE   RUNTIME   DESCRIPTION\n(empty)\n\nNo coredumps found.\n', '0')
    return None

def _cmd_bash(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'bash':
        return ResponsePlan('command_output', 'GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n', '0')
    return None

def _cmd_python(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'python' or ctx.base == 'python3':
        return ResponsePlan('command_output', 'Python 3.11.8 (main, Dec 15 2023, 12:00:00) [GCC 13.2.0] on linux\nType "help", "copyright", "credits" or "license" for more information.\n>>> ', '0')
    return None

def _cmd_perl(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base in ('perl',):
        return ResponsePlan('command_output', 'Can\'t locate object method "print" via package "leak test" (perhaps you forgot to load "leak test"?) at -e line 1.\n', '0')
    return None

def _cmd_ruby(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ruby':
        return ResponsePlan('command_output', '-:1: syntax error, unexpected end-of-input\n', '0')
    return None

def _cmd_php(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'php':
        return ResponsePlan('command_output', 'command not found\n', '127')
    return None

def _cmd_node(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base in ('node', 'go', 'rust', 'java', 'cargo', 'npm', 'yarn', 'pnpm', 'gradle', 'maven'):
        return ResponsePlan('command_not_found', f'{ctx.base}: command not found\n', '127')
    return None

def _cmd_gcc(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'gcc' or ctx.base == 'g++':
        return ResponsePlan('command_output', 'gcc: fatal error: no input files\ncompilation terminated.\n', '127')
    return None

def _cmd_make(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'make':
        return ResponsePlan('command_output', 'make: *** No targets specified and no makefile found.  Stop.\n', '127')
    return None

def _cmd_cmake(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'cmake':
        return ResponsePlan('command_not_found', 'cmake: command not found\n', '127')
    return None

def _cmd_pip(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'pip' or ctx.base == 'pip3':
        return ResponsePlan('command_output', 'Package    Version\n----------- -------\npip        24.0\nsetuptools 69.0.3\n', '0')
    return None

def _cmd_wget(ctx: _Ctx) -> ResponsePlan | None:
    # wget/curl/nc/ncat/nmap are deliberately still command_not_found: passive
    # stubs for external-network tools (no outbound traffic) come in Step 2.
    if ctx.base == 'wget' or ctx.base == 'curl' or ctx.base == 'nc' or (ctx.base == 'ncat') or (ctx.base == 'nmap'):
        return ResponsePlan('command_not_found', f'bash: {ctx.base}: command not found\n', '127')
    return None

def _cmd_history(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'history':
        return ResponsePlan('command_output', ctx.fs.cat('/root/.bash_history'), '0')
    return None

def _cmd_ping(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ping':
        return ResponsePlan('command_output', 'ping: icmp open socket: Operation not permitted\n', '127')
    return None

def _cmd_ssh(ctx: _Ctx) -> ResponsePlan | None:
    if ctx.base == 'ssh' or ctx.base == 'scp' or ctx.base == 'sftp' or (ctx.base == 'rsync'):
        return ResponsePlan('command_not_found', f'bash: {ctx.base}: command not found\n', '127')
    return None

_ROUTES: tuple = (
    _cmd_ls,
    _cmd_cat,
    _cmd_grep,
    _cmd_pwd,
    _cmd_whoami,
    _cmd_uname,
    _cmd_cd,
    _cmd_exit,
    _cmd_echo,
    _cmd_id,
    _cmd_date,
    _cmd_ps,
    _cmd_df,
    _cmd_hostname,
    _cmd_apt,
    _cmd_uptime,
    _cmd_who,
    _cmd_last,
    _cmd_w,
    _cmd_nl,
    _cmd_yes,
    _cmd_seq,
    _cmd_awk,
    _cmd_basename,
    _cmd_dirname,
    _cmd_touch,
    _cmd_mkdir,
    _cmd_rm,
    _cmd_tee,
    _cmd_cal,
    _cmd_uname_dup,
    _cmd_head,
    _cmd_tail,
    _cmd_sort,
    _cmd_uniq,
    _cmd_wc,
    _cmd_cut,
    _cmd_dd,
    _cmd_du,
    _cmd_lscpu,
    _cmd_lsblk,
    _cmd_ss,
    _cmd_netstat,
    _cmd_lsof,
    _cmd_ifconfig,
    _cmd_arp,
    _cmd_find,
    _cmd_file,
    _cmd_stat,
    _cmd_mount,
    _cmd_chmod,
    _cmd_chown,
    _cmd_ln,
    _cmd_rmdir,
    _cmd_realpath,
    _cmd_type,
    _cmd_which,
    _cmd_strings,
    _cmd_base64,
    _cmd_openssl,
    _cmd_systemctl,
    _cmd_service,
    _cmd_journalctl,
    _cmd_coredumpctl,
    _cmd_bash,
    _cmd_python,
    _cmd_perl,
    _cmd_ruby,
    _cmd_php,
    _cmd_node,
    _cmd_gcc,
    _cmd_make,
    _cmd_cmake,
    _cmd_pip,
    _cmd_wget,
    _cmd_history,
    _cmd_ping,
    _cmd_ssh,
)

def decide_response(
    protocol: str,
    session_id: str,
    action: str,
    parameters: dict,
    fs: FakeFilesystem,
    username: str = "root",
) -> ResponsePlan:
    """Answer ONE command; `protocol`/`session_id` are accepted for callers.

    Every command lives in its own small handler in _ROUTES, tried in order, so
    a single command can be read and changed without scanning the rest.
    """
    cmd = action.strip()
    ctx = _Ctx(
        cmd=cmd,
        base=cmd.split()[0] if cmd else "",
        args=parameters.get("args", []),
        cwd=parameters.get("cwd", "/"),
        fs=fs,
        username=username,
    )
    for handler in _ROUTES:
        plan = handler(ctx)
        if plan is not None:
            return plan
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

# ---------------------------------------------------------------------------
# Shell command lines: `;`, `&&` and `||` sequencing
#
# decide_response() answers ONE command. decide_line() answers a whole line the
# way a shell does, so an attacker's first reflex (`id; uname -a`, or
# `cat /etc/passwd && curl ...`) is not answered with "command not found".
#
# The session's cwd is owned by the transport shell that holds the session; the
# sequencer only tracks it for the duration of the line and hands the resulting
# value back so the transport can persist it.
# ---------------------------------------------------------------------------


def _tokenize(line: str) -> list[tuple[str, str]]:
    """Split a command line into (connector, segment) pairs.

    Connectors are `;`, `&&` and `||`; the first segment is tagged `;`. Empty
    segments are preserved so callers can tell `id;` (a real line) from `id`.
    Separators inside single/double quotes and behind a backslash are literal.
    """
    tokens: list[tuple[str, str]] = []
    buf: list[str] = []
    connector = ";"
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < len(line):
            buf.append(ch)
            buf.append(line[i + 1])
            i += 2
            continue
        two = line[i:i + 2]
        if two in ("&&", "||"):
            tokens.append((connector, "".join(buf).strip()))
            buf = []
            connector = two
            i += 2
            continue
        if ch == ";":
            tokens.append((connector, "".join(buf).strip()))
            buf = []
            connector = ";"
            i += 1
            continue
        buf.append(ch)
        i += 1
    tokens.append((connector, "".join(buf).strip()))
    return tokens

def is_chained(line: str) -> bool:
    """True when the line carries shell sequencing rather than one command."""
    return len(_tokenize(line)) > 1


def has_shell_syntax(line: str) -> bool:
    """True when the line needs the line-level path, not decide_response().

    That is sequencing (`;`, `&&`, `||`), a pipeline (`|`) or a redirection.
    """
    if is_chained(line):
        return True
    stages, red = parse_segment(line)
    return len(stages) > 1 or red.any


def _run_pipeline(
    stages: list[str],
    cwd: str,
    fs: FakeFilesystem,
    protocol: str,
    session_id: str,
    username: str,
) -> tuple[ResponsePlan, str]:
    """Run one pipeline stage by stage, feeding stdout into the next stage."""
    first = stages[0]
    plan = decide_response(
        protocol,
        session_id,
        first,
        {"args": first.split()[1:], "cwd": cwd},
        fs,
        username=username,
    )
    text, status = plan.content, plan.status

    for stage in stages[1:]:
        if status != "0":
            # The upstream complained and produced nothing to pipe; its error
            # is what the attacker sees. Bash would also run the filter on
            # empty input, which would only add a misleading status.
            break
        filtered = apply_filter(stage, text)
        if filtered is None:
            name = stage.split()[0] if stage.split() else stage
            # Unrecognised stages are refused, never guessed or forwarded.
            return ResponsePlan(
                "command_not_found", f"bash: {name}: command not found\n", "127"
            ), cwd
        text, status = filtered

    return ResponsePlan(plan.response_type, text, status), cwd


def _apply_redirections(
    plan: ResponsePlan, red, cwd: str, fs: FakeFilesystem
) -> ResponsePlan:
    """Honour a segment's redirections and record where output went."""
    if not red.any:
        return plan

    stdout_text, stderr_text = split_streams(plan.content, plan.status)
    visible, writes = visible_output(stdout_text, stderr_text, red)

    redirects = ",".join(red.targets()) or None
    for target, text in writes:
        # A redirection writes lines, so the text lands newline-terminated the
        # way a command's stdout normally is.
        if text and not text.endswith("\n"):
            text += "\n"
        if not fs.write(_resolve_path(target, cwd), text, append=red.append):
            # bash refuses an unwritable target instead of pretending it wrote.
            return ResponsePlan(
                "command_output",
                f"bash: {target}: No such file or directory\n",
                "1",
                redirect=redirects,
            )

    return ResponsePlan(
        plan.response_type,
        visible,
        plan.status,
        redirect=redirects,
    )

def _run_segment(
    segment: str,
    cwd: str,
    fs: FakeFilesystem,
    protocol: str,
    session_id: str,
    username: str,
) -> tuple[ResponsePlan, str]:
    """Run one `;`-separated segment: its pipeline, redirections and `cd`."""
    stages, red = parse_segment(segment)
    if not stages:
        # A line that is only redirections (`> /tmp/f`) still creates the file
        # and exits 0, the way bash does. Reads are never written to.
        for target in (red.stdout_target, red.stderr_target):
            if target and not is_devnull(target):
                fs.write(_resolve_path(target, cwd), "")
        return ResponsePlan("command_output", "", "0",
                            redirect=",".join(red.targets()) or None), cwd

    # `cd` is shell state, not a stage: it is never piped or redirected.
    if len(stages) == 1 and (stages[0] == "cd" or stages[0].startswith("cd ")):
        result = resolve_cd(stages[0][2:].strip(), cwd, fs)
        if result.ok:
            return ResponsePlan("command_output", "", "0"), result.cwd
        return ResponsePlan("cd_failed", result.error, "1"), cwd

    plan, new_cwd = _run_pipeline(stages, cwd, fs, protocol, session_id, username)
    return _apply_redirections(plan, red, cwd, fs), new_cwd

def decide_line(
    protocol: str,
    session_id: str,
    action: str,
    parameters: dict,
    fs: FakeFilesystem,
    username: str = "root",
) -> tuple[ResponsePlan, str]:
    """Answer a full command line; returns (plan, resulting cwd).

    `;` always continues, `&&` continues only after a zero status, `||` only
    after a non-zero one. The exit status is that of the last segment actually
    executed, and output is the concatenation of every segment that ran.
    """
    cwd = parameters.get("cwd", "/")
    if not has_shell_syntax(action):
        # One plain command: unchanged single-command behaviour.
        return decide_response(
            protocol, session_id, action, parameters, fs, username=username
        ), cwd

    tokens = _tokenize(action)
    ran: list[ResponsePlan] = []
    status = "0"
    for connector, segment in tokens:
        if not segment:
            continue
        if connector == "&&" and status != "0":
            continue
        if connector == "||" and status == "0":
            continue

        plan, cwd = _run_segment(segment, cwd, fs, protocol, session_id, username)
        status = plan.status
        if plan.response_type == "session_end":
            return ResponsePlan("session_end", plan.content, plan.status), cwd
        ran.append(plan)

    if len(tokens) <= 1:
        # A pipeline or redirection is still one command line, so its output is
        # that command's output, newline and all. Sequencing keeps its own
        # join-below behaviour, which the chaining tests pin.
        return ran[0] if ran else ResponsePlan("command_output", ""), cwd

    output = [plan.content.rstrip("\n") for plan in ran if plan.content]
    response_type = ran[-1].response_type if ran else "command_output"
    redirects: list[str] = []
    for plan in ran:
        if plan.redirect and plan.redirect not in redirects:
            redirects.append(plan.redirect)

    return ResponsePlan(
        response_type,
        "\n".join(output),
        status,
        redirect=",".join(redirects) if redirects else None,
    ), cwd


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

