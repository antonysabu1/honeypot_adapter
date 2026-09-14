# Honeypot — SSH & Telnet Adapters


## Install
```bash
pip install -r requirements.txt
```

## Run
```bash
python main.py
```

## Test SSH
```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

## Test Telnet
```bash
telnet localhost 2323
```

## Logs
All events are written to logs/honeypot.jsonl.
Each line is a JSON object with the shared schema.

## Structure

`shared/` owns everything the transports have in common; each adapter owns
only what is genuinely protocol-specific.

| Module | Owns |
|---|---|
| `shared/response_engine.py` | One handler per command in `_ROUTES` (tried in order), plus `decide_line()` for `;` / `&&` / `||` lines |
| `shared/shell.py` | Banner, prompt, argument split, keystroke handling (`LineEditor`), `cd` policy (`resolve_cd`) |
| `shared/events.py` | The single telemetry event builder |
| `shared/filesystem.py` | The fake filesystem (single owner of simulated file state) |
| `shared/mitre.py`, `shared/logger.py`, `shared/session.py` | Detection tagging, JSONL logging, session tracker |
| `ssh_adapter/` | Paramiko transport: TCP server + shell wired to the shared helpers |
| `telnet_adapter/` | Telnet framing (IAC), login state machine, its own line handling |
| `asyncssh_adapter/` | AsyncSSH transport: server + shell, selected with `HONEYPOT_SSH_ADAPTER=asyncssh` |

Data flows one way: transport reads bytes → `LineEditor` → command line →
`decide_line()` / `decide_response()` → `ResponsePlan` → transport renders it
and emits one event through `shared.events.build_event`. The transport owns the
session's cwd; the sequencer borrows it for the length of a line and hands the
resulting value back.
