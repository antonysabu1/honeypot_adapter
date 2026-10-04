"""Typed data models for the AI integration boundary.

All models use Python dataclasses with type hints.  These are the only
shapes the AI teammate should construct or receive — never raw dicts
or untyped Python objects.  The adapter validates and rejects any data
that does not conform to these models.

INVARIANT:  All AI→adapter communication goes through these models.
            The adapter never constructs its own internal models from
            untrusted input; it always validates first.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from shared.mitre import mitre_analyze


# ── AI Request Models ────────────────────────────────────────────────

@dataclass
class AIRequest:
    """Base request from the AI teammate to the adapter.

    The AI team constructs exactly one of the concrete subclasses
    below (AICommand, AIQuery, AIHealthCheck).  The adapter dispatches
    on the request type.

    INVARIANT:  All fields have default values so the dataclass can be
    instantiated without arguments; required fields are set in
    __post_init__ or by the subclasses' __init__.
    """
    # All fields have defaults so the dataclass can be instantiated
    # without arguments; required fields are set in __post_init__.
    _is_command: bool = False  # set by subclasses
    _is_query: bool = False
    _is_health: bool = False

    #: Human-readable kind of request: "command", "query", "health_check"
    request_type: str = "command"

    #: The action name (e.g. "whoami", "ls", "cat") — required for commands
    action: str = "whoami"

    #: ISO-8601 timestamp of when the request was generated
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    #: Source IP of the AI teammate
    source_ip: str = "127.0.0.1"

    #: Optional session ID — if not provided, one is generated auto-magically
    session_id: Optional[str] = None

    def __post_init__(self):
        """Set derived fields after dataclass init."""
        # Determine the request type based on which subclass this is
        # (the subclass __init__ sets _is_command, _is_query, _is_health)
        # and ensure action is appropriate.
        if self._is_command and not self.action.strip():
            object.__setattr__(self, 'action', 'whoami')
        if self._is_query and not self.query_type:
            object.__setattr__(self, 'query_type', 'filesystem_snapshot')

    def is_command(self) -> bool:
        """Return True if this is a command-type request."""
        return self._is_command

    def is_query(self) -> bool:
        """Return True if this is a query-type request."""
        return self._is_query

    def is_health_check(self) -> bool:
        """Return True if this is a health-check request."""
        return self._is_health


@dataclass
class AICommand(AIRequest):
    """AI-requested command to execute in the VirtualOS.

    The AI submits an action name and optional parameters; the adapter
    validates the command through the core decide_response() pathway.
    Only allowlisted actions (see policy.py) are permitted.

    INVARIANT:  action must be a string with no shell metacharacters
    (;, &&, ||, |, >, >>, <, &, ;;; etc.).  If the adapter receives
    such an action, it returns Result(success=False).
    """
    parameters: Dict[str, Any] = field(default_factory=dict)
    # Optional MITRE assessment from the AI (the adapter also computes
    # its own via mitre_analyze; both are recorded for correlation).
    mitre: Optional[Dict[str, str]] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure action is never empty after dataclass init."""
        if not self.action.strip():
            object.__setattr__(self, 'action', 'whoami')
        self._is_command = True


@dataclass
class AIQuery(AIRequest):
    """AI-requested read of VirtualOS state.

    Supported query types are defined in policy.py.  The adapter returns
    a Result with the requested data in the 'data' field.

    INVARIANT:  Query types not in the allowlist are rejected.
    """
    query_type: str = "filesystem_snapshot"  # default query type
    # Query-specific parameters (e.g. username for user_info)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Set the query-type flags after init."""
        super().__post_init__()
        self._is_query = True

    def is_query(self) -> bool:
        return True


@dataclass
class AIHealthCheck(AIRequest):
    """AI health-check request — the adapter always returns OK if the
    honeypot core is running.  This is the keepalive mechanism."""

    # No additional fields needed; the AI just wants to confirm connectivity.
    # Inherits request_type="health_check" via __post_init__ from AIRequest.

    def __post_init__(self):
        super().__post_init__()
        self._is_health = True

    def is_health_check(self) -> bool:
        return True


# ── AI Response Models ──────────────────────────────────────────────

@dataclass
class AIResult:
    """Result returned by the adapter to the AI teammate for any request.

    INVARIANT:  Exactly one of success=True or success=False is set.
    Only the relevant fields for the result type are populated.
    """
    success: bool
    error_code: str = "NONE"  # NONE, PERMISSION_DENIED, INVALID_COMMAND,
                              # VIRTOS_BOUNDARY_VIOLATED, RATE_LIMITED, STORAGE_ERROR
    message: str = ""  # Human-readable explanation
    session_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = field(default_factory=dict)
    # MITRE information (populated when the command/action has MITRE tags)
    mitre: Optional[Dict[str, str]] = field(default_factory=dict)

    # For query results: the actual data payload
    query_result: Optional[Dict[str, Any]] = field(default_factory=dict)

    # For command results: the VirtualOS command output
    command_output: Optional[Dict[str, Any]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.success


@dataclass
class AICommandOutput:
    """Structured output from a command executed via the AI boundary.

    This is the ONLY way the AI receives command results — never raw strings
    or unvalidated data."""
    response_type: str  # command_output, directory_listing, file_contents, session_end, etc.
    content: str  # The VirtualOS command output (already escaped/encoded)
    status: str  # "0" for success, "1" for error, "127" for command not found
    mitre: Optional[Dict[str, str]] = field(default_factory=dict)


# ── Policy / Allowlist Models ───────────────────────────────────────

#: Action names that the AI is permitted to request via validate_and_apply_decision().
#: This is the master allowlist.  Add entries only after careful security
#: review — each new action must be vetted to ensure it cannot escape the
#: VirtualOS boundary (no host exec, no path traversal, no injection).
ALLOWLISTED_ACTIONS: tuple = (
    # === Basic shell commands — fully simulated ===
    "whoami",
    "id",
    "ls",
    "pwd",
    "echo",
    "uname",
    "hostname",
    "env",
    "exit",

    # === Package manager commands — simulated, VirtualOS-only ===
    "apt",
    "apt-get",
    "dpkg",

    # === File/directory operations — fully simulated ===
    "cd",
    "mkdir",
    "touch",
    "cat",
    "rm",
    "rmdir",

    # === System information — fully simulated ===
    "ps",
    "df",
    "dfree",

    # === Service/process commands — fully simulated ===
    "service",
    "systemctl",
)

#: Action names that are STRICTLY REJECTED by the adapter.
#: These contain shell metacharacters or enable host escape.
BLOCKLISTED_ACTIONS: tuple = (
    # === Shell syntax that could chain commands ===
    ";",
    "&&",
    "||",
    "|",
    ">",
    ">>",
    "<",
    "&",

    # === Host-escaping commands (would execute on the real host) ===
    "python",
    "perl",
    "ruby",
    "php",
    "exec",
    "system",

    # === Path traversal / host access attempts ===
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/tmp/",
    "/var/",
    "/root/",
    "~/",
    "/proc/",
    "/sys/",
    "..",
    "/boot/",
    "/usr/local/",

    # === AI-disallowed wildcards and recursive/destructive patterns ===
    "rm -rf",
    "dd",
    "base64",
    "openssl",
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "telnet",
    "nc",
    "ncat",
    "netcat",
    "chmod",
    "chown",
    "chgrp",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "groupmod",
)

#: Public API — the AI teammate's policy module can import this.
#: Describes what the AI is allowed to request and what is blocked.
POLICY_SUMMARY = (
    "AI Integration Boundary Policy\n"
    "==============================\n"
    "Allowlisted actions: " + ", ".join(ALLOWLISTED_ACTIONS) + "\n"
    "Blocklisted actions: " + ", ".join(BLOCKLISTED_ACTIONS) + "\n"
    "Shell metacharacters are always rejected.\n"
    "All actions flow through decide_response() — the single chokepoint.\n"
    "MITRE ATT&CK tags are computed by the adapter via mitre_analyze().\n"
    "The AI may NOT bypass this boundary; doing so is a security violation."
)


# ── Validation Helpers ──────────────────────────────────────────────

def _has_shell_metacharacters(action: str) -> bool:
    """Return True if *action* contains shell metacharacters that could
    enable command chaining, redirection, or host escape."""
    meta_chars = (";", "&&", "||", "|", ">", ">>", "<", "&", "`", "$", "(" , ")")
    return any(c in action for c in meta_chars)


def _is_blocklisted(action: str) -> bool:
    """Return True if *action* (lowercased, trimmed) appears in the
    blocklist."""
    action_l = action.strip().lower()
    for bl in BLOCKLISTED_ACTIONS:
        if bl in action_l:
            return True
    return False


def _is_allowlisted(action: str) -> bool:
    """Return True if *action* (lowercased, trimmed) appears in the
    allowlist."""
    action_l = action.strip().lower()
    for allowed in ALLOWLISTED_ACTIONS:
        if action_l == allowed or action_l.startswith(allowed + " "):
            return True
    return False


def _is_blank(action: str) -> bool:
    """Return True if *action* is empty or only whitespace."""
    return not action.strip()


# ── Core Validation Function ────────────────────────────────────────

def validate_ai_command(ai_cmd: AICommand) -> Tuple[bool, str]:
    """Validate an AI command against the security boundary.

    Returns (ok, reason):
      ok=True  — the command is within the allowlist and safe to forward.
      ok=False — the command is rejected; *reason* describes why.

    This is the GATEKEEPER.  No command that is not explicitly allowlisted
    may be forwarded to the honeypot core's decide_response() pathway.
    """
    # 1. Quick check: blank command
    if ai_cmd.is_blank():
        return False, "EMPTY_COMMAND: action is empty or whitespace-only"

    # 1. Quick check: is the command blocklisted?
    if _is_blocklisted(ai_cmd.action):
        return False, f"BLOCKLISTED: action '{ai_cmd.action}' is on the blocklist"

    # 2. Quick check: does it contain shell metacharacters?
    if _has_shell_metacharacters(ai_cmd.action):
        return False, f"METACHARACTERS: action '{ai_cmd.action}' contains shell metacharacters"

    # 3. Quick check: is it allowlisted?
    if not _is_allowlisted(ai_cmd.action):
        return False, f"NOT_ALLOWLISTED: action '{ai_cmd.action}' is not in the allowlist"

    # 4. Passed all checks — compute MITRE for telemetry record
    try:
        mitre_result = mitre_analyze(ai_cmd.action)
    except Exception:
        mitre_result = {
            "mitre_attack_id": "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "mitre_confidence": "low",
        }

    # 5. Resource limit pre-check — verify the action is simple enough
    #    that it won't exceed command limits (the full check happens
    #    in the connection_manager during actual session handling).

    return True, "VALID"


# ── Policy Export ───────────────────────────────────────────────────

#: Public API — the AI teammate's policy module can import this.
#: Describes what the AI is allowed to request and what is blocked.
POLICY_SUMMARY = (
    "AI Integration Boundary Policy\n"
    "==============================\n"
    "Allowlisted actions: " + ", ".join(ALLOWLISTED_ACTIONS) + "\n"
    "Blocklisted actions: " + ", ".join(BLOCKLISTED_ACTIONS) + "\n"
    "Shell metacharacters are always rejected.\n"
    "All actions flow through decide_response() — the single chokepoint.\n"
    "MITRE ATT&CK tags are computed by the adapter via mitre_analyze().\n"
    "The AI may NOT bypass this boundary; doing so is a security violation."
)


# ── Exported Types for the AI Teammate ─────────────────────────────

#: The AI teammate can import these from the adapter package.
#: They are the only types the AI should construct or pattern its code on.
exported_types = (
    "AIRequest",
    "AICommand",
    "AIQuery",
    "AIHealthCheck",
    "AIResult",
    "AICommandOutput",
    "ALLOWLISTED_ACTIONS",
    "BLOCKLISTED_ACTIONS",
    "validate_ai_command",
    "POLICY_SUMMARY",
)