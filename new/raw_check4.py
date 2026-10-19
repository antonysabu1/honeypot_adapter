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
    "cat /etc/machine-id",
    "free -h",
    "cat /proc/meminfo",
    "hostname",
    "groups",
    "w",
    "cat /etc/issue",
    "type ls",
    "alias",
]

for cmd in commands:
    chan.send((cmd + "\r").encode())
    time.sleep(0.5)
    try:
        out = chan.recv(8192)
    except Exception as e:
        out = ("ERROR: " + str(e)).encode()
    print("CMD:", cmd)
    print("RAW:", repr(out))
    print("-" * 60)

chan.send(b"exit\r")
client.close()
