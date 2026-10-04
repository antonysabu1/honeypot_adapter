"""M17 AI Adapter Boundary security tests - core boundary validation."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from ai_adapter.validator import (
    validate_command_for_ai,
    validate_query_for_ai,
    ValidationResult,
)
from ai_adapter.policy import ALLOWLISTED_ACTIONS, BLOCKLISTED_ACTIONS, POLICY_SUMMARY
from ai_adapter.models import AIRequest, AICommand, AIQuery, AIResult, AICommandOutput


def test_validate_command_for_ai_blocklisted():
    """Blocklisted commands are rejected."""
    result = validate_command_for_ai(AICommand(action="/etc/passwd"))
    assert not result.valid
    assert result.error_code == "BLOCKLISTED"


def test_validate_command_for_ai_allowlisted():
    """Allowlisted commands are accepted."""
    result = validate_command_for_ai(AICommand(action="whoami"))
    assert result.valid
    assert result.error_code == "NONE"


def test_validate_command_for_ai_metacharacters():
    """Commands with shell metacharacters are rejected."""
    result = validate_command_for_ai(AICommand(action="whoami; id"))
    assert not result.valid
    assert result.error_code == "METACHARACTERS"


def test_validate_command_forai_not_allowlisted():
    """Non-allowlisted commands are rejected."""
    result = validate_command_for_ai(AICommand(action="custom_weird_action"))
    assert not result.valid
    assert result.error_code == "NOT_ALLOWLISTED"


def test_validate_query_for_ai():
    """Allowlisted queries are accepted."""
    result = validate_query_for_ai(AIQuery(request_type="query", query_type="filesystem_snapshot"))
    assert result.valid


def test_policy_summary_has_content():
    """Policy summary is non-empty string with both allowlisted and blocklisted."""
    summary = POLICY_SUMMARY
    assert isinstance(summary, str)
    assert len(summary) > 0
    assert "Allowlisted" in summary
    assert "Blocklisted" in summary


def test_allowlisted_actions_tuple():
    """Allowlisted actions tuple is non-empty with string entries."""
    assert len(ALLOWLISTED_ACTIONS) > 0
    for a in ALLOWLISTED_ACTIONS:
        assert isinstance(a, str)


def test_blocklisted_actions_tuple():
    """Blocklisted actions tuple is non-empty with string entries."""
    assert len(BLOCKLISTED_ACTIONS) > 0
    for a in BLOCKLISTED_ACTIONS:
        assert isinstance(a, str)


def test_result_success():
    """AIResult success=True is truthy."""
    r = AIResult(success=True, message="ok")
    assert bool(r)


def test_result_failure():
    """AIResult success=False is falsy."""
    r = AIResult(success=False, error_code="BLOCKLISTED")
    assert not bool(r)


def test_result_mitre():
    """AIResult can carry MITRE information."""
    r = AIResult(success=True, mitre={"mitre_attack_id": "T1059", "mitre_technique_name": "Command Scripting"})
    assert r.mitre["mitre_attack_id"] == "T1059"


def main():
    tests = [
        ("validate_command_for_ai_blocklisted", test_validate_command_for_ai_blocklisted),
        ("validate_command_for_ai_allowlisted", test_validate_command_for_ai_allowlisted),
        ("validate_command_for_ai_metacharacters", test_validate_command_for_ai_metacharacters),
        ("validate_command_forai_not_allowlisted", test_validate_command_forai_not_allowlisted),
        ("validate_query_for_ai", test_validate_query_for_ai),
        ("policy_summary_has_content", test_policy_summary_has_content),
        ("allowlisted_actions_tuple", test_allowlisted_actions_tuple),
        ("blocklisted_actions_tuple", test_blocklisted_actions_tuple),
        ("result_success", test_result_success),
        ("result_failure", test_result_failure),
        ("result_mitre", test_result_mitre),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"FAIL {name}: {type(e).__name__}: {e}")
            failed += 1

    print(f"\n=== M17 AI Boundary Test Results ===")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total:  {passed + failed}")
    if failed == 0:
        print("  ALL TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
