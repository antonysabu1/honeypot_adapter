"""Virtual shell state associated with each session.

Represents the effective shell environment for a logged-in user, including
current working directory, environment variables, umask, and identity
information.  This state is session-scoped and derived from the VirtualOS
databases (UserDatabase, GroupDatabase) rather than the host's environ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional


DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class VirtualShellState:
    """Virtual shell state for a logged-in session.

    This state is  owned by the session and persists across commands
    within that session.  It is derived from the VirtualOS databases
    (UserDatabase, GroupDatabase) and is the single source of truth
    for shell identity and environment.

    Invariants:
    - cwd always resolves to an existing directory in the virtual filesystem
    - umask is always a valid octal mode (0o###)
    - env is a dict of string-to-string key/value pairs
    - groups always includes the primary group (the user's gid)
    - PWD and OLDPWD are always consistent (never null, never broken)
    """

    # Identity
    user: str          # login username
    uid: int           # effective UID
    gid: int           # primary group GID
    groups: FrozenSet[int]  # supplementary group GIDs (includes primary gid)

    # Working directory
    cwd: str           # current working directory (always absolute, resolves in fs)
    old_pwd: str       # previous working directory (set by cd -)

    # Home directory
    home: str          # user's home directory

    # Shell environment
    shell: str         # login shell path (e.g. /bin/bash)
    term: str          # terminal type (e.g. xterm-256color)

    # Environment variables  (session-scoped)
    env: Dict[str, str] = field(default_factory=dict)

    # umask (octal string, e.g. "022")
    umask: str = "022"

    # Hostname, as configured in persona
    hostname: str = "honeypot"

    def __post_init__(self) -> None:
        """Validate invariants after object creation."""
        # Ensure cwd is absolute
        if not self.cwd.startswith("/"):
            self.cwd = "/" + self.cwd
        # Ensure old_pwd is absolute
        if self.old_pwd and not self.old_pwd.startswith("/"):
            self.old_pwd = "/" + self.old_pwd
        # Ensure umask is a valid octal string
        if self.umask:
            try:
                int(self.umask, 8)
            except ValueError:
                self.umask = "022"
        # Ensure gid is in groups
        if self.gid not in self.groups:
            self.groups = frozenset([self.gid] | set(self.groups))
        # A login shell starts with the standard environment; anything the
        # caller passed in wins.
        for name, value in (
            ("HOME", self.home),
            ("USER", self.user),
            ("SHELL", self.shell),
            ("PATH", DEFAULT_PATH),
            ("LANG", "en_US.UTF-8"),
            ("TERM", self.term),
            ("PWD", self.cwd),
        ):
            self.env.setdefault(name, value)

    def copy(self) -> "VirtualShellState":
        """Return a shallow copy of this state."""
        return VirtualShellState(
            user=self.user,
            uid=self.uid,
            gid=self.gid,
            groups=self.groups,
            cwd=self.cwd,
            old_pwd=self.old_pwd,
            home=self.home,
            shell=self.shell,
            term=self.term,
            env=dict(self.env),
            umask=self.umask,
            hostname=self.hostname,
        )

    def env_var(self, name: str, default: str | None = None) -> str:
        """Return an environment variable, falling back to default."""
        return self.env.get(name, default)

    def set_env(self, name: str, value: str) -> None:
        """Set an environment variable within this session."""
        self.env[name] = value

    def unset_env(self, name: str) -> None:
        """Remove an environment variable within this session."""
        self.env.pop(name, None)


# ── Session-state management ──────────────────────────────────────────────

# The virtual shell state is stored per-session.  The host process has
# no shell state; all state is in VirtualOS.

# The _login_user function sets the initial state when a session begins.
# The _login_user function is called from the SSH/Telnet adapters when
# a user successfully authenticates.

# ── Shell-state-aware command handlers ────────────────────────────────────

# The following handlers use ctx.shell_state (passed via _Ctx) to
# implement stateful shell behavior.  The _Ctx.dataclass must include
# a shell_state field; callers must pass it when constructing _Ctx.

# Example:
#   ctx = _Ctx(
#       cmd=cmd,
#       base=cmd.split()[0] if cmd else "",
#       args=parameters.get("args", []),
#       cwd=parameters.get("cwd", "/"),
#       fs=fs,
#       username=username,
#       identity=identity,
#       shell_state=shell_state,  # new field
#   )


# ── State transition: cd ──────────────────────────────────────────────────

# When cd succeeds:
#   old_pwd := current cwd
#   cwd := resolved path (validated against filesystem)
#   PWD env var := cwd
#   OLDPWD env var := old_pwd

# When cd fails (directory not found, not a directory, permission denied):
#   cwd unchanged
#   old_pwd unchanged
#   return error response

# When cd - succeeds:
#   cwd := old_pwd
#   old_pwd := previous cwd (before this cd)
#   PWD env var := old_pwd
#   OLDPWD env var := cwd (before the cd)

# When cd - fails (old_pwd not set or directory not accessible):
#   cwd unchanged
#   return error response
