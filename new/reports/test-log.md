# Honeypot Adapter — QA Test Log (Raw)

**Date:** 2026-09-08
**Test Environment:** localhost only, Python 3.13, paramiko 5.0.0

---

## SSH Test Output

```
=== SSH TEST BATTERY ===

--- TCP Connectivity ---
PASS: TCP connection to port 2222 established

--- SSH Handshake + Banner ---
PASS: Banner received: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1

--- Auth Prompt (password) ---
PASS: Auth succeeded with any credentials (fake auth)

--- Valid Credentials ---
PASS: Accepted admin/admin

--- Shell + Prompt Behavior ---
PASS: Welcome banner + prompt received

--- Command Execution (ls) ---
PASS: ls returns fake filesystem contents
  Output snippet: [ls\nREADME\nflag.txt\nroot@honeypot:~#]

--- Command Execution (whoami) ---
PASS: whoami returns root
  Output snippet: [whoami\nroot\nroot@honeypot:~#]

--- Command Execution (exit) ---
PASS: exit command accepted

--- Reconnect ---
PASS: Reconnect works, new session established

--- Invalid Credentials ---
PASS: Invalid credentials accepted (expected for honeypot)
```

## Telnet Test Output

```
=== TELNET TEST BATTERY ===

--- TCP Connectivity ---
PASS

--- Banner + Login Prompt ---
PASS

--- Password Prompt ---
PASS

--- Invalid Credentials + Shell ---
PASS
  [badpass\n\nroot@honeypot:~#]

--- Valid Credentials + Prompt ---
PASS

--- Command: ls ---
PASS
  [ls\nREADME\nflag.txt\nroot@honeypot:~#]

--- Command: whoami ---
PASS

--- Logout (exit) ---
PASS: exit accepted

--- Reconnect ---
PASS

--- IAC Negotiation ---
PASS: IAC handled without crash
```

## Logging Verification Output

```
Events in last batch: 80
By protocol: {'ssh': 18, 'telnet': 62}

SSH sessions: 5
SSH actions: {'ls': 1, 'connection_closed': 5, 'connection_established': 4, 'pubkey_attempt': 4, 'whoami': 2, 'exit': 2}
SSH session IDs unique: True

Telnet sessions: 20
Telnet actions: {'connection_established': 20, 'connection_closed': 20, 'login_attempt': 11, 'ls': 4, 'whoami': 4, 'exit': 3}
Telnet session IDs unique: True

Total unique session IDs: 25
No SSH/Telnet session ID overlap: True
All required fields present in all events
Events with MITRE fields: 27/80
```

## Sample Event (verified from JSONL)

```json
{
  "event_id": "0ff2ae38-13de-4dee-96ce-67625eb7b3bd",
  "timestamp": "2026-09-08T15:41:08.938412+00:00",
  "protocol": "ssh",
  "source_ip": "127.0.0.1",
  "session_id": "b6eba538-b748-4f01-a573-249b1ac4902d",
  "action": "ls",
  "parameters": {"command": "ls"},
  "raw_metadata": {},
  "session_source": "protocol_native",
  "response_status": "0",
  "response_type": "directory_listing",
  "mitre_attack_id": "T1083",
  "mitre_technique_name": "File and Directory Discovery",
  "mitre_tactic": "Discovery",
  "mitre_attack_id_secondary": "T1083",
  "mitre_technique_name_secondary": "File and Directory Discovery",
  "mitre_confidence": "high"
}
```
