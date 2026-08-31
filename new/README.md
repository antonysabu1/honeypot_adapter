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
