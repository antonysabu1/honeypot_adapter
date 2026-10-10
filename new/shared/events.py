"""Canonical telemetry event builder.

The adapter contract fixes exactly eleven top-level fields on every event. The
MITRE ATT&CK information produced by ``shared.mitre.mitre_analyze()`` is derived
metadata, so it is nested under ``raw_metadata["mitre"]`` rather than promoted to
top-level keys. ``shared.logger.log_event()`` rejects any event carrying keys
outside ``CONTRACT_KEYS``.
"""

import uuid
from datetime import datetime, timezone

# The eleven top-level fields every event must carry (the adapter contract).
CONTRACT_KEYS = (
    "event_id",
    "timestamp",
    "protocol",
    "source_ip",
    "session_id",
    "action",
    "parameters",
    "raw_metadata",
    "session_source",
    "response_status",
    "response_type",
)

# The six MITRE fields carried inside ``raw_metadata["mitre"]`` for attacker
# commands; lifecycle events leave ``raw_metadata`` empty.
MITRE_KEYS = (
    "mitre_attack_id",
    "mitre_technique_name",
    "mitre_tactic",
    "mitre_attack_id_secondary",
    "mitre_technique_name_secondary",
    "mitre_confidence",
)


def build_event(
    session_id: str,
    source_ip: str,
    protocol: str,
    action: str,
    parameters: dict,
    response_status: str,
    response_type: str,
    mitre: dict | None = None,
) -> dict:
    """Build one telemetry event carrying exactly the contract's top-level keys."""
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": protocol,
        "source_ip": source_ip,
        "session_id": session_id,
        "action": action,
        "parameters": parameters,
        "raw_metadata": {},
        "session_source": "protocol_native",
        "response_status": response_status,
        "response_type": response_type,
    }
    if mitre:
        event["raw_metadata"]["mitre"] = mitre
    return event


def mitre_of(event: dict) -> dict:
    """Return an event's MITRE tags, or ``{}`` when the event is untagged.

    Reads the nested ``raw_metadata["mitre"]`` location, falling back to the
    legacy top-level ``mitre_*`` keys so logs written before the contract fix
    still summarize correctly.
    """
    nested = (event.get("raw_metadata") or {}).get("mitre")
    if nested:
        return nested
    legacy = {k: event[k] for k in MITRE_KEYS if k in event}
    return legacy if any(v is not None for v in legacy.values()) else {}
