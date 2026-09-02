"""MITRE ATT&CK tagging for reported honeypot commands.

Maps a raw command line to the MITRE ATT&CK technique(s) it most closely
represents. Unlike a naive token→ID lookup, this module:

- Returns a **primary** technique (and, where a command is ambiguous, a
  **secondary** technique) — e.g. ``curl`` is both Ingress Tool Transfer and
  (potentially) Exfiltration.
- Is **argument-aware**: ICS protocol tokens found anywhere in the arguments
  (``modbus``, ``s7``, ``plc``, ``dnp3``, ...) upgrade the tag to the ICS
  protocol technique even when the binary is generic (``python``, ``nc``).
- Labels every technique with a human-readable **name** and a **confidence**
  (``high`` for exact binary match, ``medium`` when inferred from arguments,
  ``low`` for the default fallback).

The technique IDs are references into the MITRE ATT&CK knowledge base
(enterprise and ICS matrices). They are descriptive signals for downstream
correlation, not attribution claims.
"""

# ---------------------------------------------------------------------------
# Technique reference: ID -> (tactic, name)
# ---------------------------------------------------------------------------
TECHNIQUES = {
    # Enterprise
    "T1005": ("Collection", "Data from Local System"),
    "T1007": ("Discovery", "System Service Discovery"),
    "T1016": ("Discovery", "System Network Configuration Discovery"),
    "T1021": ("Lateral Movement", "Remote Services"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1033": ("Discovery", "System Owner/User Discovery"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1049": ("Discovery", "System Network Connections Discovery"),
    "T1053": ("Persistence", "Scheduled Task/Job"),
    "T1057": ("Discovery", "Process Discovery"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1071": ("C2", "Application Layer Protocol"),
    "T1078": ("Initial Access", "Valid Accounts"),
    "T1082": ("Discovery", "System Information Discovery"),
    "T1083": ("Discovery", "File and Directory Discovery"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1105": ("C2", "Ingress Tool Transfer"),
    "T1222": ("Defense Evasion", "File and Directory Permissions Modification"),
    "T1485": ("Impact", "Data Destruction"),
    "T1489": ("Impact", "Service Stop"),
    "T1548": ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
    "T1552": ("Credential Access", "Unsecured Credentials"),
    "T1555": ("Credential Access", "Credentials from Password Stores"),
    "T1560": ("Collection", "Archive Collected Data"),
    "T1562": ("Defense Evasion", "Impair Defenses"),
    "T1070": ("Defense Evasion", "Indicator Removal on Host"),
    # ICS
    "T0809": ("Impair Process Control", "Data Destruction"),
    "T0869": ("C2", "Standard Application Layer Protocol"),
    "T0855": ("Impair Process Control", "Unauthorized Command Message"),
    "T0859": ("Persistence", "Valid Accounts"),
    "T0861": ("C2", "Connection Proxy"),
    "T0888": ("Discovery", "System Firmware"),
}

# ---------------------------------------------------------------------------
# Command map: base token -> (primary ID, [secondary IDs])
# ---------------------------------------------------------------------------
# Discovery
COMMANDS = {
    "ls": ("T1083", ["T1083"]),
    "dir": ("T1083", ["T1083"]),
    "find": ("T1083", ["T1083"]),
    "stat": ("T1083", ["T1083"]),
    "file": ("T1083", ["T1083"]),
    "du": ("T1083", ["T1083"]),
    "cat": ("T1005", ["T1005"]),
    "pwd": ("T1082", ["T1082"]),
    "uname": ("T1082", ["T1082"]),
    "hostname": ("T1082", ["T1082"]),
    "lscpu": ("T1082", ["T1082"]),
    "lsblk": ("T1082", ["T1082"]),
    "whoami": ("T1033", ["T1033"]),
    "id": ("T1033", ["T1033"]),
    "groups": ("T1033", ["T1033"]),
    "users": ("T1033", ["T1033"]),
    "who": ("T1033", ["T1033"]),
    "w": ("T1033", ["T1033"]),
    "last": ("T1033", ["T1033"]),
    "logname": ("T1033", ["T1033"]),
    "ps": ("T1057", ["T1057"]),
    "top": ("T1057", ["T1057"]),
    "pgrep": ("T1057", ["T1057"]),
    "pidof": ("T1057", ["T1057"]),
    "ifconfig": ("T1016", ["T1016"]),
    "iwconfig": ("T1016", ["T1016"]),
    "ip": ("T1016", ["T1016"]),
    "route": ("T1016", ["T1016"]),
    "arp": ("T1016", ["T1016"]),
    "ss": ("T1049", ["T1049"]),
    "netstat": ("T1049", ["T1049"]),
    "lsof": ("T1049", ["T1049"]),
    "mount": ("T1016", ["T1016"]),
    "df": ("T1082", ["T1082"]),
    "free": ("T1082", ["T1082"]),
    "systemctl": ("T1007", ["T1007"]),
    "service": ("T1007", ["T1007"]),
    "journalctl": ("T1007", ["T1007"]),
    "env": ("T1082", ["T1082"]),
    "set": ("T1082", ["T1082"]),
    "history": ("T1555", ["T1555"]),
    "crontab": ("T1053", ["T1053"]),
    "at": ("T1053", ["T1053"]),
    "nmap": ("T1046", ["T1046"]),
    "nc": ("T1046", ["T1059"]),
    "ncat": ("T1046", ["T1059"]),
    # Execution / scripting
    "sh": ("T1059", ["T1059"]),
    "bash": ("T1059", ["T1059"]),
    "csh": ("T1059", ["T1059"]),
    "ksh": ("T1059", ["T1059"]),
    "zsh": ("T1059", ["T1059"]),
    "dash": ("T1059", ["T1059"]),
    "python": ("T1059", ["T1059"]),
    "python3": ("T1059", ["T1059"]),
    "perl": ("T1059", ["T1059"]),
    "ruby": ("T1059", ["T1059"]),
    "php": ("T1059", ["T1059"]),
    "node": ("T1059", ["T1059"]),
    "java": ("T1059", ["T1059"]),
    "awk": ("T1059", ["T1059"]),
    "sed": ("T1059", ["T1059"]),
    "expect": ("T1059", ["T1059"]),
    "gcc": ("T1059", ["T1059"]),
    "make": ("T1059", ["T1059"]),
    "vi": ("T1059", ["T1059"]),
    "vim": ("T1059", ["T1059"]),
    "nano": ("T1059", ["T1059"]),
    # Tool transfer / remote access
    "wget": ("T1105", ["T1048"]),
    "curl": ("T1105", ["T1048"]),
    "ssh": ("T1021", ["T1021"]),
    "scp": ("T1021", ["T1021"]),
    "sftp": ("T1021", ["T1021"]),
    "telnet": ("T1021", ["T1021"]),
    "rdp": ("T1021", ["T1021"]),
    "git": ("T1105", ["T1105"]),
    # Package managers (tool install)
    "apt": ("T1105", ["T1105"]),
    "apt-get": ("T1105", ["T1105"]),
    "dpkg": ("T1105", ["T1105"]),
    "yum": ("T1105", ["T1105"]),
    "pip": ("T1105", ["T1105"]),
    # System / persistence / defense
    "sudo": ("T1548", ["T1548"]),
    "chmod": ("T1222", ["T1222"]),
    "chown": ("T1222", ["T1222"]),
    "kill": ("T1489", ["T1059"]),
    "pkill": ("T1489", ["T1059"]),
    "killall": ("T1489", ["T1059"]),
    "rm": ("T1485", ["T1485"]),
    "rmdir": ("T1485", ["T1485"]),
    "tar": ("T1560", ["T1560"]),
    "gzip": ("T1560", ["T1560"]),
    "zip": ("T1560", ["T1560"]),
    "base64": ("T1027", ["T1027"]),
    "openssl": ("T1027", ["T1027"]),
    "passwd": ("T1098", ["T1552"]),
    "useradd": ("T1098", ["T1098"]),
    "userdel": ("T1098", ["T1098"]),
    "iptables": ("T1562", ["T1562"]),
    "shutdown": ("T1489", ["T1489"]),
    "reboot": ("T1489", ["T1489"]),
    "dd": ("T1485", ["T1485"]),
    "export": ("T1082", ["T1082"]),
    # ICS / SCADA protocol tooling
    "modbus": ("T0869", ["T0869"]),
    "s7comm": ("T0869", ["T0869"]),
    "dnp3": ("T0869", ["T0869"]),
    "bacnet": ("T0869", ["T0869"]),
    "enetip": ("T0869", ["T0869"]),
    "iec104": ("T0869", ["T0869"]),
    "mqtt": ("T0869", ["T0869"]),
    "snmp": ("T0869", ["T0869"]),
    "opc": ("T0869", ["T0869"]),
    "plc": ("T0869", ["T0869"]),
    "hmi": ("T0869", ["T0869"]),
    "scada": ("T0869", ["T0869"]),
    "sis": ("T0869", ["T0869"]),
    "icsconfig": ("T0869", ["T0869"]),
}

DEFAULT_TECHNIQUE = "T0859"

# Tokens that, found anywhere in a command line, signal ICS protocol activity
# even when the leading binary is generic (python, nc, bash, ...).
ICS_ARG_TOKENS = (
    "modbus", "s7", "s7comm", "dnp3", "bacnet", "enetip", "iec104",
    "mqtt", "snmp", "opc", "plc", "hmi", "scada", "sis", "ics",
)

# Argument hints that change the secondary technique of transfer tools.
_UPLOAD_HINTS = ("-T", "--upload-file", "-E", "--request", ">", "ftp://")


def mitre_analyze(command: str) -> dict:
    """Return MITRE ATT&CK metadata for a raw command line.

    Returns a dict with:
        mitre_attack_id          primary technique ID
        mitre_technique_name     primary technique name
        mitre_tactic             primary tactic
        mitre_attack_id_secondary optional secondary ID
        mitre_technique_name_secondary optional secondary name
        mitre_confidence         high | medium | low
    """
    stripped = command.strip()
    tokens = stripped.split()
    base = tokens[0].lstrip("/") if tokens else ""

    primary_id, secondary_ids = COMMANDS.get(base, (DEFAULT_TECHNIQUE, []))
    defaulted = primary_id == DEFAULT_TECHNIQUE and base not in COMMANDS

    lowered_args = " ".join(tokens[1:]).lower() if len(tokens) > 1 else ""
    arg_hit = any(tok in lowered_args for tok in ICS_ARG_TOKENS)

    secondary = None
    sec_id = None
    if arg_hit and primary_id != "T0869":
        # Generic interpreter/transfer tool being pointed at ICS endpoints
        sec_id = "T0869"
    elif secondary_ids:
        sec_id = secondary_ids[0]
    if sec_id:
        secondary = (sec_id, sec_id)

    prim_name = TECHNIQUES.get(primary_id, (None, primary_id))[1]
    prim_tactic = TECHNIQUES.get(primary_id, (None, None))[0]
    sec_name = TECHNIQUES.get(sec_id, (None, sec_id))[1] if sec_id else None

    if defaulted:
        confidence = "low"
    elif base in COMMANDS and not arg_hit:
        confidence = "high"
    else:
        confidence = "medium"

    return {
        "mitre_attack_id": primary_id,
        "mitre_technique_name": prim_name,
        "mitre_tactic": prim_tactic,
        "mitre_attack_id_secondary": sec_id,
        "mitre_technique_name_secondary": sec_name,
        "mitre_confidence": confidence,
    }


def mitre_tag(command: str) -> str:
    """Back-compat: return only the primary technique ID."""
    return mitre_analyze(command)["mitre_attack_id"]
