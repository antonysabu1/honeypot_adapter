"""Regression tests for the package command path through the real engine.

The `apt`/`apt-get` path used to call `get_filesystem()` / `get_service_manager()`
/ `get_process_manager()` without importing or defining them, so
`apt-get remove <installed>` raised ``NameError`` out of ``decide_response()``
and killed the session. These tests drive the command path exactly as a
transport does and fail if that seam raises again, and pin the resulting
VirtualOS filesystem state.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.filesystem import FakeFilesystem
from shared.response_engine import decide_response
from shared.shell import parse_args

# Sequence driven through the engine, on a fresh filesystem:
#   (command, expected status, substring of output, path, path-must-exist)
# `bash` installs/uninstalls its simulated /var/lib entry; the trailing rows are
# deterministic failures that must not raise.
SEQUENCE = (
    ("apt-get remove bash", "0", "bash removed.", "/var/lib/bash", False),
    ("apt-get install bash", "0", "bash set to installed.", "/var/lib/bash/installed", True),
    ("apt-get install bash", "1", "already installed", None, None),
    ("apt-get purge bash", "0", "bash purged.", "/var/lib/bash", False),
    ("apt-get remove nosuchpkg", "1", "not installed", None, None),
    ("apt-get install nosuchpkg", "1", "not installed", None, None),
    ("apt-get remove", "1", "Missing package name", None, None),
)


def check(label, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}: {label}{'' if cond else ' -> ' + str(detail)}")
    return cond


def main() -> bool:
    fs = FakeFilesystem()

    def run(cmd: str):
        """Drive the command path exactly as the transports do."""
        return decide_response(
            "ssh", "s-pkg", cmd, {"args": parse_args(cmd), "cwd": "/root"},
            fs, username="root",
        )

    ok = True
    for cmd, status, needle, path, must_exist in SEQUENCE:
        try:
            r = run(cmd)
        except NameError as exc:
            ok &= check(f"{cmd!r} does not raise NameError", False, exc)
            continue
        ok &= check(f"{cmd!r} -> status {status}", r.status == status, (r.status, r.content))
        ok &= check(f"{cmd!r} -> output contains {needle!r}", needle in r.content, r.content)
        if path is not None:
            ok &= check(f"{cmd!r} -> {path} exists={must_exist}",
                        fs.exists(path) == must_exist, fs.exists(path))

    # One-off details of the install that the table cannot express.
    r = run("apt-get install bash")
    ok &= check("install created /usr/share/doc/bash/copyright",
                fs.exists("/usr/share/doc/bash/copyright"))
    ok &= check("installed marker has the expected content",
                fs.cat("/var/lib/bash/installed") == "Package bash-5.1 installed\n",
                fs.cat("/var/lib/bash/installed"))

    print("\nPACKAGE PATH: " + ("ALL TESTS PASSED" if ok else "SOME TESTS FAILED"))
    return ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
