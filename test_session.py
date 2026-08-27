import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared.session import create_session_id, tracker


sid = tracker.start_session("192.168.1.5", "ssh")
print("Session ID:", sid)
print("Session data:", tracker.get_session(sid))
assert tracker.get_session(sid)["source_ip"] == "192.168.1.5"
assert tracker.get_session(sid)["session_source"] == "protocol_native"
tracker.end_session(sid)
assert tracker.get_session(sid) is None
print("ALL SESSION TESTS PASSED")