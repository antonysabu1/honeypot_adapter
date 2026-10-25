# Telnet Adapter

Protocol: Telnet (RFC 854 framing / IAC negotiation).
Default port: `2323` (`telnet.port` in `config/telnet.yaml`).

## Run

```bash
python -m telnet_adapter.server
# or start Telnet + SSH together:
python main.py
```

## Test

```bash
telnet localhost 2323
python3 test_integration_telnet.py
```

The login always succeeds (fake authentication) and the shell runs over the
VirtualOS filesystem. Every command is answered by
`shared.response_engine.decide_response()` / `decide_line()` and logged through
`shared.logger.log_event()` with the shared eleven-field event schema.
