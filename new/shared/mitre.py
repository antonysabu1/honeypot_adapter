"""MITRE ATT&CK for ICS technique mapping for reported commands.

Every logged command is tagged with the MITRE ATT&CK technique it most
closely maps to. This gives each event an attack-signal for downstream
analysis without affecting honeypot behavior.
"""

MITRE_ICS_TECHNIQUES = {
    # Discovery
    "ls": "T0842",
    "find": "T0842",
    "cat": "T0842",
    "stat": "T0842",
    "file": "T0842",
    "pwd": "T1082",
    "uname": "T0888",
    "hostname": "T0888",
    "whoami": "T0888",
    "id": "T0888",
    "ps": "T0847",
    "top": "T0847",
    "pgrep": "T0847",
    "pidof": "T0847",
    "ifconfig": "T0846",
    "ip": "T0846",
    "ss": "T0846",
    "netstat": "T0846",
    "lsof": "T0846",
    "mount": "T0846",
    "lscpu": "T0846",
    "lsblk": "T0846",
    "df": "T0890",
    "free": "T0890",
    "du": "T0890",
    "w": "T0847",
    "who": "T0847",
    "last": "T0847",
    "history": "T0847",
    # Execution
    "sh": "T0859",
    "bash": "T0859",
    "python": "T0859",
    "python3": "T0859",
    "perl": "T0859",
    "ruby": "T0859",
    "wget": "T0869",
    "curl": "T0869",
    "nc": "T0859",
    "ncat": "T0859",
    # Credential access
    "grep": "T0867",
    # Collection
    "tar": "T0861",
    "gzip": "T0861",
    "zip": "T0861",
    # Command and control
    "ssh": "T0865",
    "scp": "T0865",
    # Inhibit response function
    "kill": "T0871",
    "killall": "T0871",
    "pkill": "T0871",
    # Persistence
    "crontab": "T0897",
    "systemctl": "T0897",
    "service": "T0897",
    # ICS-specific protocol commands
    "modbus": "T0731",
    "plc": "T0731",
    "hmi": "T0815",
    "dnp3": "T0731",
    "bacnet": "T0731",
    "enetip": "T0731",
    "iec104": "T0731",
    "mqtt": "T0731",
    "snmp": "T0731",
    "opc": "T0802",
    "scada": "T0802",
    "sis": "T0802",
    "icsconfig": "T0812",
}

DEFAULT_ICS_TECHNIQUE = "T0859"


def mitre_tag(command: str) -> str:
    """Return the MITRE ATT&CK technique id for a raw command line.

    The technique is derived from the first token (command base), matching
    how the old honeypot attributed commands.
    """
    base = command.strip().split()[0].lstrip("/") if command.strip() else ""
    return MITRE_ICS_TECHNIQUES.get(base, DEFAULT_ICS_TECHNIQUE)
