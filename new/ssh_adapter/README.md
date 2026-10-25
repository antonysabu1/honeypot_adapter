# SSH Adapter

Protocol: SSH-2 (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1` banner).
Default port: `2222` (`ssh.port` in `config/ssh.yaml`).

## Run

```bash
python -m ssh_adapter.server
# or start SSH + Telnet together:
python main.py
```

The default transport is Paramiko. To use the AsyncSSH transport instead:

```bash
HONEYPOT_SSH_ADAPTER=asyncssh python main.py
```

## Test

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
python3 test_integration_ssh.py
.venv/bin/python test_integration_asyncssh.py   # needs asyncssh installed
```

The adapter accepts any password/public key (fake authentication) and runs a
fake shell over the VirtualOS filesystem. Every command is answered by
`shared.response_engine.decide_response()` / `decide_line()` and logged through
`shared.logger.log_event()` with the shared eleven-field event schema.
