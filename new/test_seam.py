"""Adapter contract, Job 3: one decision seam.

Every transport decides what to send back through one call,
``decide_response(protocol, session_id, action, parameters)``. The session's
VirtualOS state is owned by the core and found by session_id, so the call
carries no filesystem or shell objects and a future Control Engine can replace
the function's internals without any transport changing.
"""

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.response_engine import decide_response
from shared.session import tracker
from shared.session_state import get_state

TRANSPORTS = (
    "ssh_adapter/shell.py",
    "asyncssh_adapter/shell.py",
    "telnet_adapter/session.py",
)


def ask(sid: str, line: str, username: str = "root"):
    return decide_response("ssh", sid, line, {"args": line.split()[1:], "username": username})


def test_state_persists_per_session() -> None:
    sid = tracker.start_session("10.0.0.1", "ssh")
    plan = ask(sid, "cd /tmp")
    assert plan.status == "0" and plan.cwd == "/tmp", plan
    assert ask(sid, "pwd").content.strip() == "/tmp"
    assert ask(sid, "whoami", username="alice").content.strip() == "alice"
    tracker.end_session(sid)


def test_lines_go_through_the_same_seam() -> None:
    sid = tracker.start_session("10.0.0.2", "ssh")
    # Sequencing: the cd inside the line moves the session, not a copy.
    plan = ask(sid, "cd /etc; pwd")
    assert plan.content.strip() == "/etc" and plan.cwd == "/etc", plan
    assert ask(sid, "pwd").content.strip() == "/etc"
    # Environment changes made inside a line land in the session's shell.
    ask(sid, "export SEAM_VAR=42; id")
    assert get_state(sid).shell.env_var("SEAM_VAR") == "42", "export lost in a line"
    # Redirection writes land in the session's filesystem.
    ask(sid, "echo hello > /tmp/seam.txt")
    assert ask(sid, "cat /tmp/seam.txt").content.strip() == "hello"
    tracker.end_session(sid)


def test_sessions_are_isolated_and_released() -> None:
    a = tracker.start_session("10.0.0.3", "ssh")
    b = tracker.start_session("10.0.0.4", "telnet")
    ask(a, "echo secret > /tmp/only-a")
    assert ask(a, "cat /tmp/only-a").status == "0"
    assert ask(b, "cat /tmp/only-a").status != "0", "state leaked between sessions"
    tracker.end_session(a)
    # Ending a session releases its VirtualOS state.
    assert ask(a, "cat /tmp/only-a").status != "0", "state survived end_session"
    tracker.end_session(a)
    tracker.end_session(b)


def test_transports_use_only_the_seam() -> None:
    for rel in TRANSPORTS:
        tree = ast.parse((PROJECT_ROOT / rel).read_text(encoding="utf-8"))
        engine_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "shared.response_engine":
                engine_names |= {alias.name for alias in node.names}
            if isinstance(node, ast.ImportFrom) and node.module in (
                "shared.filesystem", "shared.shell_state", "shared.session_state",
            ):
                raise AssertionError(f"{rel} holds VirtualOS state ({node.module})")
        assert engine_names == {"decide_response"}, (
            f"{rel} imports {sorted(engine_names)} from the engine; only decide_response is the seam"
        )
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "decide_response"
        ]
        assert calls, f"{rel} never calls decide_response"
        for call in calls:
            assert len(call.args) == 4 and not call.keywords, (
                f"{rel}:{call.lineno} must call decide_response(protocol, session_id, action, parameters)"
            )


def main() -> None:
    test_state_persists_per_session()
    test_lines_go_through_the_same_seam()
    test_sessions_are_isolated_and_released()
    test_transports_use_only_the_seam()
    print("ALL SEAM TESTS PASSED")


if __name__ == "__main__":
    main()
