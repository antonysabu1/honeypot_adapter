import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared.filesystem import FakeFilesystem
fs = FakeFilesystem()
print("Testing FakeFilesystem...")


assert "root:x:0:0" in fs.cat("/etc/passwd"), "FAIL: /etc/passwd content wrong"
assert fs.cat("/etc/secrets") == "cat: /etc/secrets: No such file or directory", "FAIL: missing file message wrong"
assert "notes.txt" in fs.ls("/home/admin/"), "FAIL: /home/admin/ listing wrong"
assert fs.ls("/etc/passwd") == [], "FAIL: ls on file should return []"
assert fs.is_dir("/tmp/") is True, "FAIL: /tmp/ should be dir"
assert fs.exists("/bin/") is True, "FAIL: /bin/ should exist"
assert fs.is_dir("/etc/passwd") is False, "FAIL: /etc/passwd is not a dir"
assert fs.exists("/nonexistent") is False, "FAIL: /nonexistent should not exist"
assert fs.cat("/tmp/") == "cat: /tmp/: Is a directory", "FAIL: cat on dir message wrong"
print("ALL FILESYSTEM TESTS PASSED")