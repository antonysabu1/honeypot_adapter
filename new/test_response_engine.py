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


print("\nALL RESPONSE ENGINE TESTS PASSED")