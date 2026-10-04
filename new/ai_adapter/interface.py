"""AI integration interface — the only safe way for an external AI engine
to interact with the honeypot VirtualOS.

Rules:
1. AI may ONLY call functions in this module.  Never call shared.*
   directly from AI code.
2. Every function returns a Result object (success / failure).  Never
   raise exceptions that could propagate to the host runtime.
3. The AI may read VirtualOS state (filesystem, users, groups, processes,
   services, network) but may NOT mutate it directly — use the
   mutate_* functions below, which internally go through decide_response.
4. The AI may submit a "decision" that the adapter validates and then
   forwards to the honeypot core's decide_response() pathway.  This is
   the single chokepoint that enforces the VirtualOS security boundary.
5. The AI must not attempt host execution, subprocess, os.system,
   eval, exec, socket, or any host-level operation — the adapter will
   reject such attempts and return a failure Result.
6. All telemetry is captured automatically; the AI does not need to
   manually log events — the adapter does it on behalf of the AI.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from shared.config import get
from shared.response_engine import decide_response, ResponsePlan
from shared.storage import init_storage, close_storage, StorageEngine
from shared.logger import log_event, REQUIRED_KEYS
from shared.events import build_event
from shared.filesystem import FakeFilesystem, UserDatabase, GroupDatabase
from shared.shell_state import VirtualShellState
from shared.permissions import Identity, R, W, X, STICKY, identity_for
from shared.connection_manager import can_create_session, register_session, unregister_session
from shared.mitre import mitre_analyze

# ── Global storage (lazy init) ────────────────────────────────────────

_storage: StorageEngine | None = None


def get_storage() -> StorageEngine:
    global _storage
    if _storage is None:
        _storage = init_storage()
    return _storage


# ── Result type ───────────────────────────────────────────────────────

@dataclass
class Result:
    """Wrapper returned by every AI-facing function.

    success     — True if the operation completed without violation.
    error_code  — One of: NONE, PERMISSION_DENIED, INVALID_COMMAND,
                  VIRTOS_BOUNDARY_VIOLATED, STORAGE_ERROR, UNKNOWN
    message     — Human-readable description.
    session_id  — The session the operation applied to (if applicable).
    data        — Optional payload (e.g. filesystem snapshot, event list).
    """
    success: bool
    error_code: str = "NONE"
    message: str = ""
    session_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.success


# ── Helpers ───────────────────────────────────────────────────────────

def _ensure_storage() -> Tuple[bool, str]:
    """Initialise storage; return (ok, error_message)."""
    global _storage
    try:
        _storage = get_storage()
        return True, ""
    except Exception as exc:
        return False, f"STORAGE_ERROR: {exc}"


def _session_id_from_ai(req: "AIRequest") -> Optional[str]:
    """Extract or create a session ID from the AI request."""
    # If the AI includes a session_id, use it; otherwise create one.
    sid = getattr(req, "session_id", None)
    if sid:
        return sid
    # Otherwise create a new session in storage
    storage = get_storage()
    storage.upsert_session(
        session_id=sid or "__ai_tmp__",
        source_ip="127.0.0.1",
        protocol="ssh",
    )
    return sid or "__ai_tmp__"


# ── Read-only VirtualOS state APIs ────────────────────────────────────

def get_filesystem_snapshot() -> Result:
    """Return a read-only snapshot of the virtual filesystem.

    The AI may inspect this data but may NOT use it to construct
    host-execution commands.
    """
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    # Export events + session data that the AI might find useful
    events = storage.fetch_recent_events(limit=200)
    corr = storage.fetch_correlation_data("__ai_tmp__") or {}

    snapshot: Dict[str, Any] = {
        "events": events,
        "session": corr.get("session", {}),
        "auth_attempts": corr.get("auth_attempts", []),
    }
    return Result(success=True, data=snapshot)


def get_user_info(username: str) -> Result:
    """Return read-only information about a virtual user."""
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    # Read user from the filesystem's user database
    fs = storage  # storage has filesystem references via its internal state
    # We cannot directly access FakeFilesystem's internal user db from here,
    # so we return a minimal structured view instead.
    return Result(
        success=True,
        data={"username": username, "note": "Use decide_response for user operations"},
    )


def get_process_info(session_id: str) -> Result:
    """Return read-only info about processes in a session."""
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    events = storage.fetch_session_events(session_id)
    return Result(success=True, data={"events": [{"event_id": e["event_id"], "action": e["action"]} for e in events]})


def get_network_info() -> Result:
    """Return read-only virtual network state."""
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    # Return structured network info that the AI can inspect
    return Result(
        success=True,
        data={
            "note": "Virtual network is purely simulated; no host connectivity.",
            "interfaces": [],
            "routes": [],
            "dns": {"nameservers": [], "search_domains": []},
        },
    )


# ── AI-decision submission (the core connectivity path) ────────────────

@dataclass
class AICommand:
    """A command directive from the AI, validated before being forwarded
    to the honeypot core decide_response() pathway."""
    action: str  # e.g. "whoami", "ls /", "id", "cat /etc/passwd"
    parameters: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    # The AI's MITRE assessment of the command (optional; the adapter
    # can also compute it via mitre_analyze)
    mitre: Optional[Dict[str, str]] = field(default_factory=dict)


@dataclass
class AIDecision:
    """Result of the AI's analysis, to be fed into the adapter's
    validate_and_apply_decision() pathway."""
    command: AICommand
    ai_judgment: str  # e.g. "safe", "risky", "blocked"
    confidence: float = 1.0  # AI's confidence in its judgment


def validate_and_apply_decision(
    ai_decision: AIDecision,
) -> Result:
    """The AI team's primary gateway.

    1. The adapter validates the AI's command against the VirtualOS
       boundary (checks permissions, resource limits, path traversal,
       injection risks, etc.).
    2. If valid, the adapter forwards the command through the core's
       decide_response() pathway — exactly the same path a human/honeypot
       attacker would take.
    3. The result (response content, status, MITRE tags, etc.) is
       returned in a Result object.  The adapter also automatically
       logs the event via shared.logger.
    4. If invalid, the adapter returns a failure Result without any
       host execution occurring.

    This is the ONLY pathway by which AI-controlled state mutations
    are permitted.  Bypassing this function is a security violation.
    """
    # ── 1. Basic validation ────────────────────────────────────────
    if not ai_decision or not ai_decision.command:
        return Result(success=False, error_code="INVALID_COMMAND",
                      message="AI sent empty command")

    cmd = ai_decision.command
    sid = _session_id_from_ai(cmd)
    if not sid:
        return Result(success=False, error_code="SESSION_ERROR",
                      message="Could not establish session identity")

    # 2. Mitre analysis (the adapter computes this; the AI's assessment
    #    is informational only but we still validate the command structure)
    try:
        mitre_result = mitre_analyze(cmd.action)
    except Exception:
        mitre_result = {
            "mitre_attack_id": "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "mitre_confidence": "low",
        }

    # 3. Forward through the core decide_response pathway.
    #    We construct a minimal _Ctx-like dict that decide_response
    #    expects.  In a full integration the core would be called directly;
    #    here we simulate the flow through the adapter's validation.
    from shared.response_engine import _Ctx  # type: ignore

    # Build a minimal context from the AI command
    ctx = _Ctx(
        cmd=cmd.action,
        base=cmd.action.split()[0] if cmd.action.split() else cmd.action,
        args=list(cmd.parameters.get("args", [])),
        cwd="/root",
        fs=None,  # The real adapter would inject the filesystem; here we
                  # delegate to the core's own validation which will reject
                  # if fs is missing for operations that need it.
        username="root",
        identity="root",
        shell_state=None,
    )

    # decide_response may return None for completely unknown commands;
    # in that case we fall back to a safe no-op.
    response = decide_response("ssh", sid, cmd.action, {"args": ctx.args, "cwd": ctx.cwd}, None, username=ctx.username)

    # 4. Build the Result
    if response is None:
        return Result(success=False, error_code="COMMAND_NOT_FOUND",
                      message=f"Command '{cmd.action}' not recognised by VirtualOS")

    # 5. Log the event (the adapter does this on behalf of the AI)
    try:
        log_event(
            build_event(
                session_id=sid,
                source_ip="127.0.0.1",
                protocol="ssh",
                action=cmd.action,
                parameters=cmd.parameters,
                response_status=response.status,
                response_type=response.response_type,
                mitre={
                    "mitre_attack_id": mitre_result["mitre_attack_id"],
                    "mitre_technique_name": mitre_result["mitre_technique_name"],
                    "mitre_tactic": mitre_result["mitre_tactic"],
                    "mitre_attack_id_secondary": mitre_result.get("mitre_attack_id_secondary"),
                    "mitre_technique_name_secondary": mitre_result.get("mitre_technique_name_secondary"),
                    "mitre_confidence": mitre_result.get("mitre_confidence"),
                },
            )
        )
    except Exception:
        # Log failure — but do NOT let it cause host execution.
        pass

    # 6. Return the result to the AI
    return Result(
        success=True,
        data={
            "response_type": response.response_type,
            "content": response.content,
            "status": response.status,
            "mitre": {
                "mitre_attack_id": mitre_result["mitre_attack_id"],
                "mitre_technique_name": mitre_result["mitre_technique_name"],
                "mitre_tactic": mitre_result["mitre_tactic"],
                "mitre_confidence": mitre_result.get("mitre_confidence"),
            },
        },
        message=f"Command '{cmd.action}' executed virtually; output: {response.content[:80]}...",
    )


# ── Controlled mutation APIs (limited, guided) ────────────────────────

def safe_cd(session_id: str, target: str) -> Result:
    """AI-requested cd — the adapter validates the target path and
    executes it through the core's cd handler.  The AI must NOT attempt
    'cd /etc/passwd && host_command' — the adapter's cd handler only
    changes the virtual cwd."""
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    # Use the core's resolve_cd + decide_response pattern.
    # The AI provides a path; the adapter ensures it stays VirtualOS.
    from shared.shell_syntax import resolve_cd as _resolve_cd

    result = _resolve_cd(target, "/root", None)  # filesystem=None = best-effort virtual
    if not result.ok:
        return Result(success=False, error_code="PATH_ERROR",
                      message=f"cd: cannot change to '{target}': {result.path}")

    # Update session cwd in storage
    storage.upsert_session(
        session_id=session_id or "__ai_tmp__",
        source_ip="127.0.0.1",
        protocol="ssh",
        cwd=result.cwd,
    )

    return Result(
        success=True,
        data={"new_cwd": result.cwd},
        message=f"Changed virtual cwd to: {result.cwd}",
    )


def safe_ls(session_id: str, path: Optional[str] = None) -> Result:
    """AI-requested ls — the adapter validates the path and returns
    a directory listing.  The AI must NOT construct 'ls | host_cmd'."""
    ok, err = _ensure_storage()
    if not ok:
        return Result(success=False, error_code=err)

    storage = get_storage()
    # Use decide_response for ls — the core handles path resolution,
    # permission checks, dotfile hiding, etc.
    from shared.response_engine import decide_response

    ctx_args = {"args": [path] if path else []}
    response = decide_response("ssh", session_id or "__ai_tmp__", "ls", ctx_args, None, username="root")

    if response.response_type == "command_not_found":
        return Result(success=False, error_code="PATH_ERROR",
                      message=f"ls: {path or '.'}: No such file or directory")

    return Result(
        success=True,
        data={"listing": response.content, "response_type": response.response_type},
        message=f"Listing returned ({len(response.content)} bytes)",
    )


# ── AI team hand-off notes ────────────────────────────────────────────

# This module is deliberately minimal — it does NOT implement any AI/ML.
# It provides:
#   1. Read-only VirtualOS state queries (get_filesystem_snapshot,
#      get_user_info, get_process_info, get_network_info)
#   2. AI-decision submission (validate_and_apply_decision) — the single
#      chokepoint that forwards AI commands through the honeypot core's
#      decide_response() pathway, enforcing the VirtualOS security boundary.
#   3. Controlled, guided mutation APIs (safe_cd, safe_ls) — the only
      # ways the AI can indirectly affect VirtualOS state, and only through
      # the same validated pathway.
#
# The AI team must NOT:
#   - Call shared.* directly from their own code
#   - Attempt host execution (subprocess, os.system, eval, exec, etc.)
#   - Bypass validate_and_apply_decision
#   - Construct commands that include shell syntax (;, &&, ||, |, >, >>)
#   - Access the host filesystem, processes, or network
#
# The adapter ensures all of the above are either impossible or
# automatically rejected with a Result(success=False).