# Honeypot — SSH & Telnet Adapters


## Requirements

- Python 3.10+
- `paramiko` + `PyYAML` — required (`requirements.txt`)
- `asyncssh` — optional, only for the experimental AsyncSSH SSH transport (`requirements-asyncssh.txt`)

A missing `asyncssh` does **not** disable the honeypot: the Paramiko and Telnet
listeners still start.

## Install
```bash
pip install -r requirements.txt           # required
pip install -r requirements-asyncssh.txt  # optional AsyncSSH transport
```

## Run
```bash
python main.py
```

## Configuration

Settings live in `config/` (`ssh.yaml`, `telnet.yaml`, `honeypot.yaml`,
`limits.yaml`, `persona.yaml`).

| Setting | Source | Default |
|---|---|---|
| SSH adapter | `HONEYPOT_SSH_ADAPTER` env, else `ssh.adapter` | `paramiko` (`asyncssh` experimental) |
| SSH port | `ssh.port` | `2222` |
| Telnet port | `telnet.port` | `2323` |
| Log / DB | `honeypot.log_dir` | `logs/honeypot.jsonl`, `logs/honeypot.db` |
| Limits | `limits.yaml` | `max_sessions: 100`, `max_commands_per_session: 500`, … |

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
Each line is a JSON object with the shared schema (exactly the eleven contract
fields: `event_id`, `timestamp`, `protocol`, `source_ip`, `session_id`, `action`,
`parameters`, `raw_metadata`, `session_source`, `response_status`,
`response_type`). MITRE ATT&CK tags are nested under `raw_metadata["mitre"]`;
protocol fingerprint data such as `client_version` and `terminal_type` is
carried alongside it in `raw_metadata`.

## Tests

Run from `new/`. The suites are plain scripts — no test runner required; a
non-zero exit means failure.

```bash
python3 test_startup.py                 # imports + host-isolation guard
python3 test_packages.py                # apt install/remove through the engine
python3 test_filesystem.py              # core VirtualOS suites
python3 test_response_engine.py
python3 test_integration_ssh.py         # Paramiko transport (needs paramiko)
python3 test_integration_telnet.py      # Telnet transport
PYTHONPATH=. python3 -m ai_adapter.tests.test_ai_boundary   # AI adapter boundary
```

For the optional AsyncSSH transport, use a virtualenv that has `asyncssh`:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-asyncssh.txt
.venv/bin/python test_integration_asyncssh.py
```

## Simulation & isolation guarantee

SSH and Telnet are answered entirely inside the VirtualOS. Every command goes
through `shared.response_engine.decide_response()` / `decide_line()` against an
in-memory `FakeFilesystem`, virtual users/groups/permissions, and virtual
services. No `old/` reference code is invoked.

Attacker input is never executed on the host: the attacker-facing command path
imports no `subprocess`/`pty`/`socket` and calls no `os.system`/`eval`/`exec`
(`test_startup.py` enforces this statically). Redirection (`>`, `>>`, `2>`, …)
writes only to the simulated filesystem, and reading a host path does not
disclose host content — both are asserted by `test_startup.py`.

## Structure

`shared/` owns everything the transports have in common; each adapter owns
only what is genuinely protocol-specific.

| Module | Owns |
|---|---|
| `shared/response_engine.py` | One handler per command in `_ROUTES` (tried in order), plus `decide_line()` for `;` / `&&` / `||` lines |
| `shared/shell.py` | Banner, prompt, argument split, keystroke handling (`LineEditor`), `cd` policy (`resolve_cd`) |
| `shared/shell_syntax.py` | Pipelines and redirections (`>`, `>>`, `2>`, `2>&1`, `&>`, `<`, `/dev/null`): parsing, filter stages, which stream is hidden. Pure — it knows no commands, so the engine still runs every stage. The engine's `grep`/`head`/`tail`/`cut`/`sort`/`uniq`/`wc` handlers call these same filters |
| `shared/events.py` | The single telemetry event builder |
| `shared/filesystem.py` | The fake filesystem (single owner of simulated file state), including the identity databases: `UserDatabase` → `VirtualUser` and `GroupDatabase` → `VirtualGroup`. `/etc/passwd` and `/etc/group` are *generated* from these (`refresh_etc()`), never kept beside them. Primary group membership lives in `VirtualUser.gid`; `VirtualGroup.members` holds supplementary members only, which is what keeps the two files consistent |
| `shared/mitre.py`, `shared/logger.py`, `shared/session.py` | Detection tagging, JSONL logging, session tracker |
| `ssh_adapter/` | Paramiko transport: TCP server + shell wired to the shared helpers |
| `telnet_adapter/` | Telnet framing (IAC), login state machine, its own line handling |
| `asyncssh_adapter/` | AsyncSSH transport: server + shell, selected with `HONEYPOT_SSH_ADAPTER=asyncssh` |

Data flows one way: transport reads bytes → `LineEditor` → command line →
`decide_line()` / `decide_response()` → `ResponsePlan` → transport renders it
and emits one event through `shared.events.build_event`. The transport owns the
session's cwd; the sequencer borrows it for the length of a line and hands the
resulting value back.
