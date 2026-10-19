import sys
import paramiko
import time

host = sys.argv[1]
port = int(sys.argv[2])
username = sys.argv[3] if len(sys.argv) > 3 else "root"
password = sys.argv[4] if len(sys.argv) > 4 else "pass"

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, port=port, username=username, password=password,
                look_for_keys=False, allow_agent=False, timeout=10)
chan = client.invoke_shell()
chan.settimeout(5.0)
time.sleep(0.5)
chan.recv(8192)

commands = [
    "uname -a",
    "cat /proc/version",
    "env",
    "sudo -l",
    "crontab -l",
    "netstat -tuln",
    "ss -tuln",
    "who",
    "last",
    "uptime",
    "df -h",
    "mount",
    "lscpu",
    "cat /sys/class/dmi/id/product_name",
    "cat /proc/cpuinfo | grep hypervisor",
    "dmesg | tail -5",
    "which python3",
    "which gcc",
    "arp -a",
    "route -n",
    "cat /etc/shadow",
    "sudo whoami",
]

for cmd in commands:
    chan.send((cmd + "\r").encode())
    time.sleep(0.6)
    try:
        out = chan.recv(8192)
    except Exception as e:
        out = ("ERROR: " + str(e)).encode()
    print("CMD:", cmd)
    print("RAW:", repr(out))
    print("-" * 60)

chan.send(b"exit\r")
client.close()

