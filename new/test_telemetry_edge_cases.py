import json, socketserver, sys, tempfile, threading, time
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
import paramiko
import shared.logger as logger_mod
from ssh_adapter.server import SSHHandler

def _start_server(tmp_dir):
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SSHHandler)
    tcp.allow_reuse_address = True
    tcp.daemon_threads = True
    port = tcp.server_address[1]
    t = threading.Thread(target=tcp.serve_forever, daemon=True)
    t.start()
    return tcp, port

def _read_events(log_file):
    if not log_file.exists():
        return []
    return [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]

def _recv_until(chan, marker, timeout=8.0):
    chan.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = chan.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

CONTRACT = {"event_id", "timestamp", "protocol", "source_ip", "session_id", "action", "parameters", "raw_metadata", "session_source", "response_status", "response_type"}

def _assert_contract(events, context):
    for e in events:
        assert set(e) == CONTRACT, f"[{context}] mismatch: {sorted(e.keys())}"

def test_failed_auth():
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-edge-auth-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"
    tcp, port = _start_server(tmp_dir)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="root", password="wrongpassword", look_for_keys=False, allow_agent=False, timeout=10)
        chan = client.invoke_shell()
        _recv_until(chan, b"# ")
        chan.send(b"exit\r")
        time.sleep(0.5)
    except Exception:
        pass
    finally:
        client.close()
        tcp.shutdown()
        tcp.server_close()
    time.sleep(0.3)
    events = _read_events(logger_mod.LOG_FILE)
    assert events
    actions = [e["action"] for e in events]
    assert "login_attempt" in actions
    _assert_contract(events, "failed_auth")

def test_malformed_input():
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-edge-malformed-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"
    tcp, port = _start_server(tmp_dir)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="root", password="pass", look_for_keys=False, allow_agent=False, timeout=10)
        chan = client.invoke_shell()
        _recv_until(chan, b"# ")
        chan.send(b"\x00\xff\xfe\x80\x81malformed\r")
        time.sleep(0.5)
        _recv_until(chan, b"# ", timeout=3.0)
        chan.send(b"exit\r")
        time.sleep(0.5)
    except Exception:
        pass
    finally:
        client.close()
        tcp.shutdown()
        tcp.server_close()
    time.sleep(0.3)
    events = _read_events(logger_mod.LOG_FILE)
    assert events
    _assert_contract(events, "malformed_input")

def test_chained_command_partial_failure():
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-edge-chain-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"
    tcp, port = _start_server(tmp_dir)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="alice", password="pass", look_for_keys=False, allow_agent=False, timeout=10)
        chan = client.invoke_shell()
        _recv_until(chan, b"# ")
        chan.send(b"whoami && nonexistentcmd\r")
        _recv_until(chan, b"# ", timeout=5.0)
        chan.send(b"exit\r")
        time.sleep(0.5)
    finally:
        client.close()
        tcp.shutdown()
        tcp.server_close()
    time.sleep(0.3)
    events = _read_events(logger_mod.LOG_FILE)
    assert events
    _assert_contract(events, "chained_partial_failure")
    resp_types = {e["response_type"] for e in events}
    assert "command_not_found" in resp_types

def test_disconnect_without_exit():
    tmp_dir = Path(tempfile.mkdtemp(prefix="honeypot-edge-disconnect-"))
    logger_mod.LOG_DIR = tmp_dir
    logger_mod.LOG_FILE = tmp_dir / "honeypot.jsonl"
    tcp, port = _start_server(tmp_dir)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="root", password="pass", look_for_keys=False, allow_agent=False, timeout=10)
        chan = client.invoke_shell()
        _recv_until(chan, b"# ")
        chan.send(b"whoami\r")
        _recv_until(chan, b"# ", timeout=5.0)
        chan.close()
        client.close()
        time.sleep(1.0)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
        tcp.shutdown()
        tcp.server_close()
    time.sleep(0.3)
    events = _read_events(logger_mod.LOG_FILE)
    assert events
    _assert_contract(events, "disconnect_without_exit")
    actions = [e["action"] for e in events]
    assert "connection_closed" in actions
    session_ids = {e["session_id"] for e in events}
    assert len(session_ids) == 1
