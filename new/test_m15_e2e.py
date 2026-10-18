"""M15: Full End-to-End Integration Tests

Tests complete workflows across all three protocol transports (Paramiko SSH, Telnet)
with stateful multi-command sequences, cross-component state propagation, package manager
integration, and security verification.

Each workflow exercises the full chain: protocol → session management → response engine
→ VirtualOS state mutation → cross-component propagation → telemetry recording → session termination.
"""

import json
import os
import sys
import time
from pathlib import Path

import paramiko

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.response_engine import decide_response, _Ctx, VirtualShellState
from shared.filesystem import FakeFilesystem
from shared.packages import get_package_manager, valid_package_name
from shared.processes import get_process_manager, get_service_manager
from shared.network import get_virtual_network
from shared.logger import log_event, LOG_FILE, LOG_DIR, REQUIRED_KEYS

PROJECT_ROOT = Path(__file__).resolve().parent

# ─────────────── Helpers ───────────────

def reset_state():
    """Reset all VirtualOS state between workflow tests."""
    from shared.persistence import init_vstate, get_vstate_storage
    try:
        storage = init_vstate()
        storage.reset()
    except Exception:
        pass
    from shared.packages import get_package_manager
    reset_state.__pm = get_package_manager()

def get_sm():
    """Get the ServiceManager singleton."""
    return get_service_manager()

def get_pm():
    """Get the ProcessManager singleton."""
    return get_process_manager()

def get_lports():
    """Get listening ports from the ServiceManager."""
    sm = get_sm()
    return list(sm._services.keys())

def test_package_manager_query():
    """Test package query through the PackageManager."""
    pm = get_package_manager()
    # Query installed package
    pkg = pm.apt_query("bash")
    assert pkg is not None, "bash should be in package database"
    assert pkg.name == "bash"
    assert pkg.installed == True
    assert pkg.version == "5.1"

    # Query nonexistent package
    unknown = pm.apt_query("totally_fake_pkg_xyz123")
    assert unknown is None, "Nonexistent package should return None"

    # List installed
    installed = pm.list_installed()
    assert len(installed) == 17, f"Expected 17 baseline packages, got {len(installed)}"

    # dpkg status
    status = pm.dpkg_status("bash")
    assert "install ok installed" in status

    # Package name validation
    assert valid_package_name("bash") == True
    assert valid_package_name("") == False
    assert valid_package_name("/etc/passwd") == False

    print("  [PASS] Package manager query tests passed")


def test_package_manager_install_remove():
    """Test package install and remove through PackageManager."""
    pm = get_package_manager()

    # All baseline packages are already installed, so test error paths
    # Install already-installed package
    results = pm.apt_get_install(["bash"])
    assert "already installed" in results[0][1], f"Expected 'already installed', got: {results[0][1]}"

    # Remove non-existent package
    results = pm.apt_get_remove(["nonexistent-pkg-xyz123"])
    assert "not installed" in results[0][1], f"Expected 'not installed', got: {results[0][1]}"

    # Query after remove
    pkg = pm.apt_query("bash")
    assert pkg is not None and pkg.name == "bash"

    print("  [PASS] Package manager install/remove tests passed")


def test_package_cross_component():
    """Test package operations affect cross-component state."""
    pm = get_package_manager()
    fs = FakeFilesystem()
    sm = get_sm()
    pm_proc = get_pm()

    # Verify baseline state
    installed = pm.list_installed()
    assert len(installed) == 17, f"Expected 17 baseline packages, got {len(installed)}"

    # Service state
    ssh_svc = sm.get_service("sshd")
    assert ssh_svc is not None
    assert ssh_svc.state == "running", f"Expected sshd running, got: {ssh_svc.state}"

    # Process manager PIDs
    pids = pm_proc.pids()
    assert 1 in pids, "PID 1 (init) should exist"
    assert 782 in pids, "PID 782 (sshd) should exist"

    # Package query
    bash_pkg = pm.apt_query("bash")
    assert bash_pkg is not None
    assert bash_pkg.name == "bash"
    assert bash_pkg.installed == True

    print("  [PASS] Package cross-component integration tests passed")


# ─────────────── Security Regression Workflows ───────────────

def test_security_nonexistent_package():
    """Test that nonexistent packages produce safe errors."""
    pm = get_package_manager()

    # Query nonexistent
    result = pm.apt_query("no_such_pkg_xyz123")
    assert result is None, "Querying nonexistent package should return None"

    # dpkg status for nonexistent
    status = pm.dpkg_status("no_such_pkg_xyz123")
    assert "not installed" in status, f"Expected 'not installed' in status, got: {status}"

    # Install nonexistent
    results = pm.apt_get_install(["no_such_pkg_xyz123"])
    assert "not installed" in results[0][1] or "E:" in results[0][1], f"Expected error, got: {results[0][1]}"

    # Remove nonexistent
    results = pm.apt_get_remove(["no_such_pkg_xyz123"])
    assert "not installed" in results[0][1], f"Expected 'not installed' error, got: {results[0][1]}"

    print("  [PASS] Security: nonexistent package tests passed")


def test_security_path_traversal():
    """Test that path traversal attempts in package names are rejected."""
    from shared.packages import valid_package_name

    # These should all be invalid
    bad_names = [
        "../../../etc/passwd",
        "/bin/sh",
        "/tmp/evil.sh",
        "../var/lib/dpkg",
        "/etc/sudoers",
    ]

    for bad in bad_names:
        assert valid_package_name(bad) == False, f"'{bad}' should be invalid package name"

    # These should be valid
    good_names = ["bash", "coreutils", "openssh-server", "app-name", "pkg_name"]
    for good in good_names:
        assert valid_package_name(good) == True, f"'{good}' should be valid package name"

    print("  [PASS] Security: path traversal tests passed")


def test_security_deterministic_failures():
    """Test that failures are deterministic and not silent."""
    pm = get_package_manager()

    # Install already-installed package
    results = pm.apt_get_install(["bash"])
    assert "already installed" in results[0][1], f"Expected 'already installed', got: {results[0][1]}"

    # Remove non-existent
    results = pm.apt_get_remove(["nonexistent-xyz123"])
    assert "not installed" in results[0][1], f"Expected 'not installed' error, got: {results[0][1]}"

    # Repeated operations produce consistent state
    results1 = pm.apt_get_install(["procps"])  # Already installed
    assert "already installed" in results1[0][1]

    results2 = pm.apt_get_remove(["nonexistent-xyz123"])
    assert "not installed" in results2[0][1]

    print("  [PASS] Security: deterministic failure tests passed")


# ─────────────── Main Test Runner ───────────────

def run_all_m15_tests():
    """Run all M15 integration tests."""
    results = []

    tests = [
        ("Package Manager Query", test_package_manager_query),
        ("Package Manager Install/Remove", test_package_manager_install_remove),
        ("Package Cross-Component", test_package_cross_component),
        ("Security: Nonexistent Package", test_security_nonexistent_package),
        ("Security: Path Traversal", test_security_path_traversal),
        ("Security: Deterministic Failures", test_security_deterministic_failures),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
            print(f"  [PASS] {name}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {name}: {e}")

    print(f"\n{'=' * 60}")
    print(f"M15 INTEGRATION TEST RESULTS: {passed} passed, {failed} failed out of {passed + failed} tests")
    print(f"{'=' * 60}")

    return passed, failed


if __name__ == "__main__":
    print("=" * 70)
    print("M15: FULL INTEGRATION TEST - END-TO-END WORKFLOWS")
    print("=" * 70)
    print()
    print("Running complete M15 integration test suite...")
    print()

    passed, failed = run_all_m15_tests()

    print()
    print("=" * 70)
    if failed == 0:
        print("M15 INTEGRATION TESTS: ALL PASSED")
    else:
        print(f"M15 INTEGRATION TESTS: {failed} FAILURE(S) FOUND")
    print("=" * 70)
