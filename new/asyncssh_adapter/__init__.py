"""AsyncSSH-based SSH transport adapter (experimental).

Replaces the Paramiko transport while keeping the honeypot core
(response_engine / FakeFilesystem / mitre / logger / session_tracker)
unchanged. Selectable via HONEYPOT_SSH_ADAPTER=asyncssh in main.py.
"""