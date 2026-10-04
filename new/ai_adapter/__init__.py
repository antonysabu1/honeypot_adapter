"""AI integration adapter for the honeypot honeypot.

This module provides a safe, structured boundary between the honeypot's
VirtualOS and an external AI teammate.  The AI team interacts with this
adapter through well-defined Python types; the adapter validates every
input and translates it into honeypot core operations (decide_response,
filesystem mutations, telemetry events).  No AI/ML code lives in this
repo — only the connective interface that enforces the security invariant:
all AI-controlled commands must operate only on validated VirtualOS
abstractions and may never execute host shell commands, filesystem
operations, process controls, or network operations.
"""

from __future__ import annotations

from . import interface, models, validator, policy  # noqa: F401  # expose public API