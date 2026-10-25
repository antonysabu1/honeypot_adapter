"""Per-session VirtualOS state, owned by the core and keyed by session_id.

Transports never hold a filesystem or shell state of their own: they hand
``decide_response()`` a session_id and the engine looks the state up here.
That keeps the decision seam at (session_id, action, parameters), so the
engine behind it can be replaced without touching any transport.

State is created on a session's first command and dropped when the session
ends (``shared.session.SessionTracker.end_session``).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass

from shared.filesystem import FakeFilesystem
from shared.shell_state import VirtualShellState


@dataclass
class SessionState:
    fs: FakeFilesystem
    shell: VirtualShellState


_STATES: dict[str, SessionState] = {}
# Paramiko serves each connection on its own thread.
_LOCK = threading.Lock()


_LURE_COMPANIES = [
    "NexusTech", "OrionHealth", "PinnacleLogistics", "MeridianSystems", "VanguardMfg",
]
_LURE_DOMAINS = [
    "nexus-tech.internal", "orion-health.local", "pinnacle-log.corp",
    "meridian-sys.lan", "vanguard-mfg.net",
]
_LURE_USERS = [
    ["jmartinez", "schen", "akowalski"],
    ["rthompson", "lgarcia", "mjohnson"],
    ["dwilliams", "nkim", "bpetersen"],
    ["tadams", "jlee", "cbrooks"],
    ["epatel", "mwong", "kanderson"],
]


def _lure_index(session_id: str) -> int:
    return int(hashlib.md5(session_id.encode()).hexdigest(), 16) % len(_LURE_COMPANIES)


def _seed_lures(fs: FakeFilesystem, session_id: str) -> None:
    """Seed the fake filesystem with realistic-looking credential lure files.

    Each session gets a deterministic but unique set of fake company names,
    usernames, and credentials so that an attacker reading these files cannot
    reuse them across sessions. The content looks genuine enough to attract
    further interaction (and trigger logging) without disclosing real data.
    """
    idx = _lure_index(session_id)
    company = _LURE_COMPANIES[idx]
    domain = _LURE_DOMAINS[idx]
    users = _LURE_USERS[idx]
    # Deterministic fake key material (not a real key — just looks like one).
    key_hex = hashlib.sha256(session_id.encode()).hexdigest()
    fake_key_id = f"AKIA{key_hex[:16].upper()}"
    fake_secret  = key_hex[16:56]
    db_pass = hashlib.md5((session_id + "db").encode()).hexdigest()[:16]
    ssh_key_body = "\n".join(
        key_hex[i:i+64] for i in range(0, len(key_hex * 4), 64)
    )[:768]

    fs.mkdir("/root/.aws")
    fs.write_file("/root/.aws/credentials",
        f"[default]\naws_access_key_id = {fake_key_id}\n"
        f"aws_secret_access_key = {fake_secret}\nregion = us-east-1\n"
    )
    fs.mkdir("/root/.ssh")
    fs.write_file("/root/.ssh/id_rsa",
        f"-----BEGIN RSA PRIVATE KEY-----\n{ssh_key_body}\n-----END RSA PRIVATE KEY-----\n",
        mode=0o600,
    )
    fs.write_file("/root/.ssh/id_rsa.pub",
        f"ssh-rsa AAAA{key_hex[:40]}== root@{domain}\n"
    )
    fs.mkdir("/var/www/html")
    fs.write_file("/var/www/html/config.php",
        f"<?php\n$db_host = 'localhost';\n$db_name = '{company.lower()}_prod';\n"
        f"$db_user = '{users[0]}';\n$db_pass = '{db_pass}';\n"
        f"$db_port = 3306;\n?>\n"
    )
    fs.mkdir("/etc/mysql")
    fs.write_file("/etc/mysql/my.cnf",
        f"[client]\nuser={users[0]}\npassword={db_pass}\nhost=localhost\n"
    )
    fs.write_file("/root/.bash_history",
        f"ssh {users[1]}@{domain}\n"
        f"mysql -u {users[0]} -p{db_pass} {company.lower()}_prod\n"
        f"cat /root/.aws/credentials\n"
        f"aws s3 ls s3://{domain.split('.')[0]}-backups/\n"
        f"scp {users[2]}@{domain}:/var/backups/dump.sql .\n"
    )


def _new_state(username: str, session_id: str = "") -> SessionState:
    # The honeypot always presents a root shell; only whoami reflects the
    # actual login user (per session-isolation report recommendation).
    fs = FakeFilesystem()
    _seed_lures(fs, session_id or username)
    return SessionState(
        fs=fs,
        shell=VirtualShellState(
            user=username,
            uid=0,
            gid=0,
            groups=frozenset([0]),
            cwd="/root",
            old_pwd="/",
            home="/root",
            shell="/bin/bash",
            term="xterm-256color",
        ),
    )


def get_state(session_id: str, username: str = "root") -> SessionState:
    """Return the session's state, creating it on first use."""
    with _LOCK:
        state = _STATES.get(session_id)
        if state is None:
            state = _STATES[session_id] = _new_state(username, session_id)
        return state


def session_cwd(session_id: str, username: str = "root") -> str:
    """The session's current directory (a new channel starts where it is)."""
    return get_state(session_id, username).shell.cwd


def drop_state(session_id: str) -> None:
    """Forget a finished session's state."""
    with _LOCK:
        _STATES.pop(session_id, None)
