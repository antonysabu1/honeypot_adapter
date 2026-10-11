"""Fresh-clone startup and host-isolation regression tests.

Pins three properties a clean checkout must have:

1. The application imports without any untracked module (the previous gap:
   tracked code imported ``shared.shell_state`` / ``shared.permissions`` that
   were never committed).
2. The attacker-facing command path contains no host-execution primitives.
3. Attacker-controlled input cannot read or write the real host filesystem;
   shell redirection lands in the in-memory VirtualOS filesystem only.

No real listener is started; the checks run against the response engine and a
throwaway FakeFilesystem, so this test has no host-side effects.
"""

import ast
import importlib
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Every module the running application needs. ``main`` is import-safe
# (its listeners only start under ``if __name__ == "__main__"``).
APP_MODULES = (
    "shared.config",
    "shared.filesystem",
    "shared.permissions",
    "shared.shell_state",
    "shared.shell",
    "shared.shell_syntax",
    "shared.response_engine",
    "shared.events",
    "shared.logger",
    "shared.mitre",
    "shared.session",
    "shared.storage",
    "shared.packages",
    "ssh_adapter.server",
    "ssh_adapter.shell",
    "telnet_adapter.server",
    "telnet_adapter.session",
    "ai_adapter.interface",
    "main",
)

# Files that handle attacker-controlled input. They must never reach a host
# process, host network, or host filesystem.
COMMAND_PATH = (
    "shared/filesystem.py",
    "shared/permissions.py",
    "shared/shell_state.py",
    "shared/shell.py",
    "shared/shell_syntax.py",
    "shared/response_engine.py",
    "shared/packages.py",
    "ssh_adapter/shell.py",
    "telnet_adapter/session.py",
    "asyncssh_adapter/shell.py",
)

_FORBIDDEN_MODULES = {"subprocess", "pty", "socket"}
_FORBIDDEN_CALLS = {
    "os.system", "os.popen", "os.fork", "eval", "exec", "pty.spawn",
}


def _dotted(node) -> str:
    """Return a dotted name for an attribute/name node, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _forbidden_in_source(path: Path) -> list[str]:
    """AST-based scan, so comments/docstrings cannot cause false positives."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _FORBIDDEN_MODULES:
                    hits.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _FORBIDDEN_MODULES:
                hits.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in _FORBIDDEN_CALLS or name.startswith(("os.exec", "os.spawn")):
                hits.append(f"{name}()")
    return hits


def check(label: str, cond: bool, detail: object = "") -> bool:
    print(f"  {'PASS' if cond else 'FAIL'}: {label}{'' if cond else ' -> ' + str(detail)}")
    return cond


def main() -> bool:
    ok = True

    # 1) Import the whole application from this checkout.
    for module in APP_MODULES:
        try:
            importlib.import_module(module)
            print(f"  PASS: import {module}")
        except Exception as exc:  # noqa: BLE001 - report the exact blocker
            ok &= check(f"import {module}", False, f"{type(exc).__name__}: {exc}")

    try:
        importlib.import_module("asyncssh_adapter.server")
        print("  PASS: import asyncssh_adapter.server (asyncssh installed)")
    except ImportError as exc:
        print(f"  SKIP: asyncssh_adapter.server (optional dependency: {exc})")

    # 2) The telemetry contract must stay eleven top-level fields.
    from shared.events import CONTRACT_KEYS
    ok &= check("event contract has 11 fields", len(CONTRACT_KEYS) == 11, CONTRACT_KEYS)

    # 3) Static guard: no host-execution primitives in the command path.
    for rel in COMMAND_PATH:
        hits = _forbidden_in_source(PROJECT_ROOT / rel)
        ok &= check(f"no host-exec primitives in {rel}", not hits, hits)

    # 4) Behavioural isolation: attacker input cannot touch the host.
    from shared.filesystem import FakeFilesystem
    from shared.response_engine import decide_line
    from shared.shell import parse_args

    def run(cmd: str, fs: FakeFilesystem):
        args = parse_args(cmd)
        resp, _cwd = decide_line(
            "ssh", "s-iso", cmd, {"args": args, "cwd": "/root"}, fs, username="root"
        )
        return resp

    host_write = f"/tmp/hp_iso_write_{os.getpid()}"
    host_secret = f"/tmp/hp_iso_secret_{os.getpid()}"
    host_virtual = "/tmp/hp_iso_vfile"
    for leftover in (host_write, host_secret, host_virtual):
        try:
            os.unlink(leftover)
        except OSError:
            pass
    try:
        fs = FakeFilesystem()

        run(f"echo pwned > {host_write}", fs)
        ok &= check(
            "redirection did not create the host path",
            not os.path.exists(host_write), host_write,
        )

        with open(host_secret, "w", encoding="utf-8") as fh:
            fh.write("HOSTSECRET123")
        resp = run(f"cat {host_secret}", fs)
        ok &= check(
            "host file content is not exposed",
            "HOSTSECRET123" not in (resp.content or ""), resp.content,
        )

        run("echo hello > /tmp/vfile", fs)
        read_back = run("cat /tmp/vfile", fs)
        ok &= check(
            "virtual write/read round-trips in the VirtualOS",
            "hello" in (read_back.content or ""), read_back.content,
        )
        ok &= check(
            "virtual write did not fall through to the host",
            not os.path.exists("/tmp/vfile"),
        )
    finally:
        for leftover in (host_write, host_secret):
            try:
                os.unlink(leftover)
            except OSError:
                pass

    print("\nSTARTUP/ISOLATION: " + ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
