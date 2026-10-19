import sys
import paramiko
import time

def recv_until(chan, marker, timeout=5.0):
    chan.settimeout(timeout)
    buf = b""
    while marker not in buf:
        try:
            chunk = chan.recv(4096)
            if not chunk:
                break
            buf += chunk
        except Exception:
            break
    return buf

def run_cmd(chan, cmd):
    chan.send((cmd + "\r").encode())
    time.sleep(0.3)
    out = recv_until(chan, b"# ", timeout=3.0)
    return out.decode("utf-8", errors="ignore")

def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3] if len(sys.argv) > 3 else "root"
    password = sys.argv[4] if len(sys.argv) > 4 else "pass"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password,
                    look_for_keys=False, allow_agent=False, timeout=10)
    chan = client.invoke_shell()
    recv_until(chan, b"# ", timeout=5.0)

    checks = []

    out = run_cmd(chan, "whoami")
    user = out.split("\n")[0].strip()
    checks.append(("whoami", user, user in ["root", "alice", "bob"]))

    out = run_cmd(chan, "wc -l /etc/passwd")
    try:
        count = int(out.split()[0])
    except Exception:
        count = 0
    checks.append(("passwd lines", str(count), count < 5))

    out = run_cmd(chan, "ps aux | wc -l")
    try:
        count = int(out.split()[0])
    except Exception:
        count = 0
    checks.append(("process count", str(count), count < 5))

    out = run_cmd(chan, "ifconfig")
    checks.append(("network", "127 only" if "127.0.0.1" in out and "eth" not in out else "has iface",
                   "127.0.0.1" in out and "eth" not in out))

    out = run_cmd(chan, "history | wc -l")
    try:
        count = int(out.split()[0])
    except Exception:
        count = 0
    checks.append(("bash history", str(count), count == 0))

    run_cmd(chan, "touch /tmp/marker.txt")
    out = run_cmd(chan, "find /tmp -name marker.txt | wc -l")
    try:
        count = int(out.split()[0])
    except Exception:
        count = 0
    checks.append(("file persistence", "vanished" if count == 0 else "persists", count == 0))

    chan.send(b"exit\r")
    client.close()

    print("")
    print("CHECK RESULTS")
    print("-" * 60)
    flagged = 0
    for name, value, suspicious in checks:
        mark = "FLAG" if suspicious else "OK"
        if suspicious:
            flagged += 1
        print(name.ljust(20), value.ljust(20), mark)
    print("-" * 60)
    print("Flagged:", flagged, "/", len(checks))
    if flagged >= 3:
        print("VERDICT: Likely a honeypot")
    else:
        print("VERDICT: Looks real")

main()
