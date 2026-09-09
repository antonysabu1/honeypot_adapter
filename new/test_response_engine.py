import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared.response_engine import decide_response, ResponsePlan
from shared.filesystem import FakeFilesystem
fs = FakeFilesystem()


r = decide_response("ssh", "uuid-123", "cat /etc/passwd", {"args": ["/etc/passwd"]}, fs)
assert r.response_type == "file_contents"
assert "root:x:0:0" in r.content
assert r.status == "0"
print("✓ cat /etc/passwd works")


r = decide_response("ssh", "uuid-123", "whoami", {}, fs)
assert r.content == "root"
assert r.status == "0"
print("✓ whoami works")


r = decide_response("ssh", "uuid-123", "ls", {"args": ["/etc"]}, fs)
assert r.response_type == "directory_listing"
assert r.status == "0"
print("✓ ls /etc works")


r = decide_response("ssh", "uuid-123", "hacked", {}, fs)
assert r.response_type == "command_not_found"
assert "127" == r.status
assert "hacked: command not found" in r.content
print("✓ unknown command works")


r = decide_response("telnet", "uuid-456", "exit", {}, fs)
assert r.response_type == "session_end"
assert r.content == "logout"
print("✓ exit works")


# New commands added per the security reports
r = decide_response("ssh", "uuid-123", "whoami", {}, fs, username="admin")
assert r.content == "admin", r.content
print("✓ whoami returns login username")


r = decide_response("ssh", "uuid-123", "echo hello world", {"args": ["/root/hello", "/root/world"]}, fs)
assert r.content == "hello world", r.content
print("✓ echo returns its argument")


r = decide_response("ssh", "uuid-123", "id", {}, fs)
assert r.content == "uid=0(root) gid=0(root) groups=0(root)", r.content
print("✓ id works")


r = decide_response("ssh", "uuid-123", "date", {}, fs)
assert "UTC" in r.content and "2026" in r.content, r.content
print("✓ date works")


r = decide_response("ssh", "uuid-123", "ps", {}, fs)
assert "sshd" in r.content, r.content
print("✓ ps works")


r = decide_response("ssh", "uuid-123", "history", {}, fs)
assert "wget" in r.content, r.content
print("✓ history works")


r = decide_response("ssh", "uuid-123", "ls -la /root", {"args": ["-la", "/root"], "cwd": "/root"}, fs)
assert ".bash_history" in r.content and "flag.txt" in r.content, r.content
print("✓ ls -la shows dotfiles")


r = decide_response("ssh", "uuid-123", "ls /root", {"args": ["/root"], "cwd": "/root"}, fs)
assert ".bash_history" not in r.content and "flag.txt" in r.content, r.content
print("✓ plain ls hides dotfiles")


print("\nALL RESPONSE ENGINE TESTS PASSED")