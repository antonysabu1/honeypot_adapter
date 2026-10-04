"""AI adapter validation — the enforcement layer that sits between
the AI teammate and the honeypot core.

This module is the enforcement arm of the security boundary.  It is
called by the adapter's public functions (interface.validate_and_apply_decision,
safe_cd, safe_ls) and also by the model validation (models.validate_ai_command).

The invariant is: NO AI-generated input may bypass this validator.
All paths lead through here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .models import AICommand, AIResult, validate_ai_command, ALLOWLISTED_ACTIONS, BLOCKLISTED_ACTIONS, POLICY_SUMMARY
from .policy import POLICY_SUMMARY as POLICY_SUMMARY_EXPLICIT


@dataclass
class ValidationResult:
    """Result of validating an AI command.

    Used internally by the adapter and also exposed to the AI teammate
    via the AIResult model when a command is rejected."""
    valid: bool
    error_code: str  # NONE, BLOCKLISTED, METACHARACTERS, NOT_ALLOWLISTED, STORAGE_ERROR
    message: str  # Human-readable reason
    mitre: Optional[Dict[str, str]] = None  # MITRE tags if the command was analysable


def validate_command_for_ai(ai_cmd: AICommand) -> ValidationResult:
    """Core validation entry point.

    This is the function that the adapter calls before forwarding any
    AI command to the core decide_response() pathway.  It enforces the
    security boundary rules defined in policy.py and models.py.

    Returns a ValidationResult; the adapter converts this into an
    AIResult (success=False) before returning to the AI teammate.
    """
    # 1. Quick check: is the command blocklisted?
    
    # 1. Quick check: is the command blocklisted?
    action_l = ai_cmd.action.strip().lower()
    blocklisted_list = [
        "/etc/passwd", "/etc/shadow", "/etc/hostname",
        "/tmp/", "/var/", "/root/", "~",
        "/proc/", "/sys/", "..", "/boot/", "/usr/local/",
        "rm -rf", "dd", "base64", "openssl",
        "curl", "wget", "ssh", "scp", "sftp",
        "telnet", "nc", "ncat", "netcat",
        "chmod", "chown", "chgrp",
        "useradd", "userdel", "usermod",
        "groupadd", "groupdel", "groupmod",
    ]
    if action_l in blocklisted_list:
        return ValidationResult(
            valid=False,
            error_code="BLOCKLISTED",
            message=f"Command '{ai_cmd.action}' is on the blocklist (see AI policy)",
        )

    # 2. Quick check: does it contain shell metacharacters?
    from .models import _has_shell_metacharacters
    if _has_shell_metacharacters(ai_cmd.action):
        return ValidationResult(
            valid=False,
            error_code="METACHARACTERS",
            message=f"Command '{ai_cmd.action}' contains shell metacharacters",
        )

    # 3. Quick check: is it allowlisted?
    from .models import _is_allowlisted
    if not _is_allowlisted(ai_cmd.action):
        return ValidationResult(
            valid=False,
            error_code="NOT_ALLOWLISTED",
            message=f"Command '{ai_cmd.action}' is not in the allowlist",
        )

    # 4. Passed all checks — the command is valid.  Compute MITRE for
    #    the telemetry record that will be generated later.
    from .models import mitre_analyze
    try:
        mitre = mitre_analyze(ai_cmd.action)
    except Exception:
        mitre = {
            "mitre_attack_id": "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "mitre_confidence": "low",
        }

    return ValidationResult(
        valid=True,
        error_code="NONE",
        message="Command validated successfully",
        mitre=mitre,
    )


def validate_query_for_ai(ai_query: "AIQueryInternal") -> ValidationResult:
    """Validate an AI query request.

    Currently a stub — only allowlisted query types are permitted.
    """
    from .models import AIQuery
    if not isinstance(ai_query, AIQuery):
        return ValidationResult(
            valid=False,
            error_code="INVALID_TYPE",
            message="Request is not a valid AIQuery type",
        )

    # Only allowlisted query types may proceed
    from .policy import ALLOWLISTED_ACTIONS  # reuse policy allowlist
    # For now, only "filesystem_snapshot" and simple queries are allowed
    if ai_query.query_type not in ("filesystem_snapshot", "user_info", "process_info", "network_info"):
        return ValidationResult(
            valid=False,
            error_code="NOT_ALLOWLISTED_QUERY",
            message=f"Query type '{ai_query.query_type}' is not allowlisted",
        )

    return ValidationResult(
        valid=True,
        error_code="NONE",
        message="Query validated successfully",
    )


def policy_summary() -> str:
    """Return the human-readable policy summary for display/logging."""
    from .policy import POLICY_SUMMARY
    return POLICY_SUMMARY_EXPLICIT


# ── AI-Team Exported Types ─────────────────────────────────────────

#: The AI teammate can import ValidationResult from the adapter to
#: understand why their command was rejected.  The adapter always
#: returns an AIResult (success=False with appropriate error_code)
# when validation fails, but the underlying ValidationResult is
#  available for introspection.
exported_types = (
    "ValidationResult",
    "validate_command_for_ai",
    "validate_query_for_ai",
    "policy_summary",
)


def is_allowlisted(action: str) -> bool:
    """Quick check — is *action* in the allowlist?  Used by the AI team
    to pre-validate before submitting to the full adapter."""
    from .models import _is_allowlisted
    return _is_allowlisted(action)


def is_blocklisted(action: str) -> bool:
    """Quick check — is *action* on the blocklist?  Used by the AI team
    to pre-validate before submitting to the full adapter."""
    
    return _is_blocklisted(action)


# Role: enforce the security boundary.  No AI-generated command may bypass
# this validator.  All adapter public functions call into this module
# before any VirtualOS interaction.  The invariant is strict: if this
# validator returns valid=False, the adapter must never forward the
# command to decide_response() or any other core pathway.