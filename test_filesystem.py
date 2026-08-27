import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared.filesystem import FakeFilesystem

fs = FakeFilesystem()
print(fs.cat("/etc/passwd"))
assert "root:x:0:0" in fs.cat("/etc/passwd")
assert fs.cat("/etc/secrets") == "cat: /etc/secrets: No such file or directory"
assert "notes.txt" in fs.ls("/home/admin/")
assert fs.is_dir("/tmp/") is True
assert fs.exists("/bin/") is True
print("ALL FILESYSTEM TESTS PASSED")