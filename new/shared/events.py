"""Canonical telemetry event builder.

Every transport emits the same event schema, so the builder lives here rather
than being copied into each adapter. `mitre` is merged in when the caller has
run shared.mitre.mitre_analyze() over the command; lifecycle events leave those
fields null.
"""

import uuid
from datetime import datetime, timezone

# Fields shared.mitre.mitre_analyze() supplies for attacker commands.
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
    """Build one telemetry event in the schema shared.logger expects."""
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
        # Lifecycle events are not attacker commands, so MITRE fields are null.
        "mitre_attack_id": None,
        "mitre_technique_name": None,
        "mitre_tactic": None,
        "mitre_attack_id_secondary": None,
        "mitre_technique_name_secondary": None,
        "mitre_confidence": None,
    }
    if mitre:
        event.update(mitre)
    return event
