"""AI integration policy — the allowlist/blocklist and validation policy
for the AI adapter boundary.

This module is the single source of truth for what the AI teammate
may and may not do.  It is intentionally small and reviewable —
the security of the entire boundary rests on this file being correct.

RULES (enforced by validate_ai_command in models.py):
1. Every action must be in ALLOWLISTED_ACTIONS (positive check).
2. No action may contain shell metacharacters (blocklist check).
3. No action may match BLOCKLISTED_ACTIONS (path traversal, host escape,
   host exec patterns, wildcard patterns).
4. All actions flow through decide_response() — the single chokepoint.
5. MITRE ATT&CK tags are computed by the adapter via mitre_analyze().
6. The AI may NOT bypass this boundary; doing so is a security violation.
"""

from __future__ import annotations

#: Action names that the AI is permitted to request via the adapter's
#: validate_and_apply_decision() pathway.  This is the master
#: allowlist.  Each entry is a fully simulated VirtualOS command —
#: none of these invoke host execution, subprocess, os.system, eval,
#: exec, or any host-level operation.
#
#: New entries may only be added after a security review.  The pattern
#: for adding a new allowlisted action is:
#:   1. Verify the command is 100% simulated in shared.response_engine.
#:   2. Verify no host filesystem/process/network access is possible.
#:   3. Add to this tuple; update POLICY_SUMMARY in models.py.
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

#: Action names that are STRICTLY REJECTED by the adapter.  If the AI
#: submits any of these, the adapter returns Result(success=False) with
#: error_code=BLOCKLISTED.  These contain shell metacharacters, enable
#: command chaining/redirection, enable host escape, or are otherwise
#: dangerous in a honeypot context.
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
    "shell",
    "python",
    "perl",
    "ruby",
    "php",
    "exec",
    "system",
    "`",  # backtick command substitution

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
    "/lib/",
    "/usr/local/",

    # === AI-disallowed wildcards and recursive/ destructive patterns ===
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

#: Public API — the AI teammate's model module can import this.
#: Describes what the AI is allowed to request and what is blocked.
POLICY_SUMMARY = (
    "AI Integration Boundary Policy\n"
    "==============================\n"
    "Allowlisted actions: " + ", ".join(ALLOWLISTED_ACTIONS) + "\n"
    "Blocklisted actions: " + ", ".join(BLOCKLISTED_ACTIONS) + "\n"
    "Shell metacharacters are always rejected (>, <, |, &&, ||, ;, &, `, $, (, )).\n"
    "All actions flow through decide_response() — the single chokepoint.\n"
    "MITRE ATT&CK tags are computed by the adapter via mitre_analyze().\n"
    "The AI may NOT bypass this boundary; doing so is a security violation."
)