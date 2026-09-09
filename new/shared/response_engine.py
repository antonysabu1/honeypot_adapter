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
    day = f"{now.day:2d}"
    return f"{now:%a %b} {day} {now:%H:%M:%S} UTC {now:%Y}"


def decide_response(
    protocol: str,
    session_id: str,
    action: str,
    parameters: dict,
    fs: FakeFilesystem,
    username: str = "root",
) -> ResponsePlan:
    command = action.strip()

    if action.strip().startswith("ls"):
        args = parameters.get("args", [])
        # Flags like -la stay untouched; strip any cwd-prefixed pseudo-paths.
        path_args = [a for a in args if not a.startswith("-")]
        show_all = any(a.startswith("-") and "a" in a for a in args)
        if path_args:
            path = path_args[0]
        else:
            path = parameters.get("cwd", "/")
        contents = fs.ls(path)
        if not show_all:
            contents = [c for c in contents if not c.startswith(".")]
        content_str = "\n".join(contents) if contents else ""
        return ResponsePlan("directory_listing", content_str, "0")

    if command.startswith("cat "):
        args = parameters.get("args", [""])
        path = args[0] if args and args[0] else command[4:].strip()
        return ResponsePlan("file_contents", fs.cat(path), "0")

    if command == "pwd":
        return ResponsePlan("command_output", "/root", "0")

    if command == "whoami":
        return ResponsePlan("command_output", username or "root", "0")

    if command == "uname" or command.startswith("uname "):
        return ResponsePlan(
            "command_output",
            "Linux honeypot 5.15.0-105-generic "
            "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux",
            "0",
        )

    if command == "cd" or command.startswith("cd "):
        return ResponsePlan("command_output", "", "0")

    if command == "exit":
        return ResponsePlan("session_end", "logout", "0")

    base = command.split()[0] if command else ""

    if base == "echo":
        return ResponsePlan("command_output", command[5:].strip(), "0")

    if base == "id":
        return ResponsePlan("command_output", "uid=0(root) gid=0(root) groups=0(root)", "0")

    if base == "date":
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

    if base == "history":
        return ResponsePlan("command_output", fs.cat("/root/.bash_history"), "0")

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

    if base == "uptime":
        return ResponsePlan(
            "command_output",
            f"{_fake_date()} up 2 days,  3:12,  1 user,  load average: 0.00, 0.01, 0.05",
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

    return ResponsePlan(
        "command_not_found",
        f"bash: {command}: command not found",
        "127",
    )