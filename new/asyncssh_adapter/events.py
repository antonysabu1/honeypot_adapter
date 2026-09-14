"""Event builder mirroring the schema used by the existing adapters.

Keeps the shared logging schema byte-for-byte compatible with the events
emitted by ssh_adapter/server.py so the two transports are drop-in
replacements for telemetry consumers.
"""

import uuid
from datetime import datetime, timezone


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
    """Build an event dict conforming to shared.logger.REQUIRED_KEYS."""
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
        "mitre_attack_id": None,
        "mitre_technique_name": None,
        "mitre_tactic": None,
        "mitre_attack_id_secondary": None,
        "mitre_technique_name_secondary": None,
        "mitre_confidence": None,
    }
    if mitre:
        for key, value in mitre.items():
            event[key] = value
    return event