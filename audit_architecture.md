# HONEYPOT COMPLETE TECHNICAL AUDIT
## 3. ACTUAL ARCHITECTURE

### ASCII Diagram (based on current code)

```
┌──────────────────────────────────────────────────────────────────────┐
│                      ATTACKER CONNECTION                          │
│                                                                     │
│  +----------------------+                                       │
│  |    SSH / TELNET      |                                       │
│  |  TCP:2222/2323       |                                       │
│  +----------┬-----------+                                       │
│              │                                           │
│  │              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |   PROTOCOL ADAPTERS  |                                   │
│  |  +-----------------+                               │
│  |  | ssh_adapter/     |   Paramiko implementation      │
│  |  | asyncssh_adapter/|   AsyncSSH implementation        │
│  |  | telnet_adapter/  |   RFC 854 IAC, login state machine   │
│  +----------┬-----------+                               │
│              │                                           │
│  │              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |    SESSION LAYER     |                                   │
│  |  +-----------------+                               │
│  |  | shared/session.py|   SessionTracker, create_session_id()│
│  |  +----------┬------+                               │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |   SHELL ENGINE      |                                   │
│  |  +-----------------+                               │
│  |  | shared/response_engine.py | 50+ cmd handlers,     │
│  |  |  decide_response() |  decide_line() for ;/&&/||     │
│  |  |  _ROUTES array |  Pipeline/redirection parsing       │
│  |  +----------┬------+                               │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  | VIRTUAL LINUX       |                                   │
│  |  +-----------------+                               │
│  |  | shared/filesystem.py | Inode-based tree,           │
│  |  |  492+ lines      |  permissions, ownership, timestamps   │
│  |  +----------┬------+                               │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  TELEMETRY / STORAGE|                                   │
│  |  +-----------------+                               │
│  |  | shared/events.py | Event builder, MITRE tags       │
│  |  | shared/logger.py | JSONL writer, schema validation │
│  |  | shared/storage.py| SQLite: sessions, events,     │
│  |  |                 |  auth_attempts, commands, techniques  │
│  |  +----------┬------+                               │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |   DEFENDER TOOLS   |                                   │
│  |  (FUTURE)          │                                   │
│  +----------------------+                                   │
└──────────────────────────────────────────────────────────────────────┘

### Runtime Execution Path

ATTACKER INPUT
  │
  ▼
│  +----------------------+                                   │
│  |  SSH/Telnet        |   Paramiko/AsyncSSH/Telnet      │
│  |  (transport)       │                                       │
│  +----------┬-----------+                                       │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  CONNECTION MANAGER |   can_create_session()/register_session()│
│  |  (shared/connection_manager.py) │                    │
│  +----------┬-----------+                                       │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  SESSION LAYER      |   SessionTracker, cwd tracking      │
│  +----------┬-----------+                                       │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  SHELL ENGINE       |   decide_response()/decide_line() │
│  |  (shared/response_engine.py) │                    │
│  +----------┬-----------+                                       │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  VIRTUAL OS         |   FakeFilesystem (Inode model)      │
│  |  (shared/filesystem.py) │                    │
│  +----------------------+                                   │
│              │                                           │
│  ▼              ▼                                           │
│  +----------------------+                                   │
│  |  TELEMETRY / STORAGE│   events.py, logger.py, storage.py  │
│  +----------------------+                                   │
└──────────────────────────────────────────────────────────────────────┘
"""
<tool_call>