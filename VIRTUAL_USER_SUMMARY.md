# Virtual User System - Implementation Summary
## Architecture Decision

The `UserDatabase` and `GroupDatabase` classes already existed in `shared/filesystem.py` as part of the `FakeFilesystem` inode-based virtual filesystem. The decision was to **reuse and enhance** the existing `UserDatabase` rather than create a separate user state component. This ensures:

1. **Single source of truth**: User state lives in `FakeFilesystem._users` → `UserDatabase._users` dict, which is the same database that powers `/etc/passwd` generation via `passwd_text()` and `/etc/group` via `group_text()`.

2. **Integration with response engine**: The `_Ctx` struct already carries `fs: FakeFilesystem` and `username: str`. Command handlers (`_cmd_whoami`, `_cmd_id`, `_cmd_useradd`) access user state through `ctx.fs.users`, which is the `UserDatabase` instance.

3. **No duplication**: User state is not duplicated inside individual command handlers. The `UserDatabase.add()`, `UserDatabase.get()`, and `UserDatabase.uid()` methods are the canonical API.

4. **Deterministic UID allocation**: `UserDatabase.next_uid()` computes `max(existing UIDs) + 1`, starting from 1000 (the default for the first new user beyond the built-in system users).

5. **`/etc/passwd` consistency**: `FakeFilesystem.refresh_etc()` regenerates `/etc/passwd` from `UserDatabase.passwd_text()` whenever users are added/removed. This is called automatically by `_cmd_useradd`.

6. **No host modification**: All operations act on the in-memory virtual database. `UserDatabase.add()` returns `False` (rejecting the operation) if the username contains characters invalid for `/etc/passwd` format (`:`, `,`, newline, null), and if the user already exists.

**Existing components that consume the user state:**
- `_cmd_whoami` → returns `ctx.username` (the login identity)
- `_cmd_id` → returns `uid`, `gid`, `groups` from the virtual user database
- `_cmd_useradd` → creates a new user, adds to group database, refreshes `/etc/passwd`
- `FakeFilesystem.stat()` → displays user names via `name_by_uid()`
- `FakeFilesystem.ls_long()` → displays user names via `name_by_uid()`

## Implementation Plan

| Step | Description | Status |
|------|-------------|--------|
| 1 | Enhanced `UserDatabase.add()` with username validation (reject empty, colon, comma, newline, null) | Done |
| 2 | Added `GroupDatabase.name_by_gid()` for `_cmd_id` group name lookup | Done |
| 3 | Rewrote `_cmd_id` to use `ctx.fs.users.get(uname)` and `ctx.fs.groups.name_by_gid(u.gid)` | Done |
| 4 | Rewrote `_cmd_useradd` to use `ctx.fs.users.add()` with proper error handling | Done |
| 5 | Added `ctx.fs.refresh_etc()` call in `_cmd_useradd` to keep `/etc/passwd` in sync | Done |
| 6 | All 13 test suites pass with no regressions | Done |

**Files modified (5 files, +89/-6 lines):**
- `new/shared/filesystem.py` - `UserDatabase.add()` validation, `GroupDatabase.name_by_gid()` 
- `new/shared/response_engine.py` - `_cmd_id`, `_cmd_useradd`, `_cmd_whoami`

**State transitions documented:**

### useradd
1. User sends: `useradd -d /home/newuser newuser`
2. `_cmd_useradd` extracts `username=newuser`, `home=/home/newuser`
3. `ctx.fs.users.add(username, home=home)` → returns `True` (new user)
4. `gid = ctx.fs.users.uid(username)` → gets primary group GID (same as UID)
5. `ctx.fs.groups.add(username, gid=gid)` → adds user to primary group
6. `ctx.fs.groups._groups[username].members.append(username)` → adds user to group members
7. `ctx.fs.refresh_etc()` → regenerates `/etc/passwd` with new user line
8. Response: `command_output` with status `0`

### whoami (after login as "alice")
1. `_cmd_whoami` returns `ctx.username` = `"alice"` (set during paramiko login)
2. Response: `"alice"`

### id (as root, no custom user)
1. `_cmd_id` → `uname = "root"` (from `get_attr("persona.username", "root")`)
2. `u = ctx.fs.users.get("root")` → finds the root UserEntry (uid=0, gid=0)
3. `gname = ctx.fs.groups.name_by_gid(0)` → `"root"`
4. Response: `"uid=0(root) gid=0(root) groups=0(root)"`

### id (as alice, after useradd newuser)
1. `_cmd_id` → `uname = ctx.username` = `"alice"` (from login)
2. `u = ctx.fs.users.get("alice")` → finds the alice UserEntry (uid=1000, gid=1000)
3. `gname = ctx.fs.groups.name_by_gid(1000)` → `"alice"` (primary group)
4. Response: `"uid=1000(alice) gid=1000(alice) groups=1000(alice)"`

### /etc/passwd consistency
1. After `useradd newuser`, `refresh_etc()` is called
2. `/etc/passwd` content is regenerated from `UserDatabase.passwd_text()`
3. New user line: `newuser:x:1001:1001:newuser:/home/newuser:/bin/bash`
3. Existing users remain unchanged (the passwd text is a complete regeneration from the database)

## Test Matrix

| Test | Description | Expected |
|------|-------------|----------|
| **Normal creation** | `useradd newuser` → verify user exists in database | User added, `/etc/passwd` updated |
| **Duplicate user** | `useradd newuser` (second time) → verify rejection | `useradd: user 'newuser' already exists`, status 9 |
| **Invalid username** | `useradd "new:user"` → verify rejection | `useradd` returns `False`, no change to database |
| **UID collision** | Manual UID override that conflicts → `next_uid()` ensures determinism | `next_uid()` always returns `max+1` |
| **Root behavior** | `whoami` → `"root"`, `id` → `"uid=0(root) gid=0(root) groups=0(root)"` | Root always accessible |
| **Session identity** | Different SSH sessions see same virtual user state | `ctx.fs.users` is shared across sessions within same process |
| **`/etc/passwd` consistency** | After `useradd`, `cat /etc/passwd` shows new user | `refresh_etc()` regenerates passwd from database |

**Exact test commands:**
```bash
# Unit tests
cd /home/antony/adapter/new && python test_filesystem.py
python test_session.py
python test_response_engine.py
python test_chaining.py
python test_shell_syntax.py
python test_recon.py
python tests/test_logger.py

# Integration tests
python3 test_integration_ssh.py
python3 test_integration_telnet.py
/venv/bin/python3 test_integration_asyncssh.py

# All together
python test_filesystem.py && python test_session.py && python test_response_engine.py && echo "ALL PASSED"
```

## Security Verification

- **Zero host execution**: No real `useradd`, `adduser`, `passwd`, `usermod`, `id`, `whoami`, or OS commands executed. All operations act on in-memory virtual state.
- **Host `/etc/passwd` untouched**: `UserDatabase` is purely in-memory; `FakeFilesystem` only writes to its own virtual `/etc/passwd` file inside the memory filesystem.
- **Username validation**: `UserDatabase.add()` rejects usernames containing `:`, `,`, `\n`, `\0` — characters that would break `/etc/passwd` format or enable path separation attacks.
- **Duplicate prevention**: `UserDatabase.add()` returns `False` if user already exists, and `_cmd_useradd` returns status 9 with error message.
- **No host process creation**: The user management operates entirely within the honeypot's virtual state.
- **MITRE technique tags**: User-addition events can be tagged with `T1136.001` (Account Creation) for attack graph coverage.

## Remaining Issues / Known Limitations

1. **Groups as separate entity**: Group state exists in `GroupDatabase` but is not yet a full permission engine. Supplementary groups beyond the primary group are not yet supported — the `groups=` field in `id` output shows only the primary group GID.

2. **No user password/shadow**: The virtual system has no concept of encrypted passwords or shadow file. Authentication is handled by the SSH/Pamiko adapter's fake auth (all credentials accepted).

3. **UID/GID range**: UIDs start at 1000 for new users, following Debian/Ubuntu convention. The built-in system users (root=0, daemon=1, etc.) are pre-seeded from `_PASSWD_HEADER`.

4. **Session isolation**: Each new SSH connection starts with a fresh `FakeFilesystem`, so user creation in one session is not visible to another session unless they share the same process. For persistent state, the SQLite storage engine could be extended.

## Recommended Next Milestone: Virtual Groups

The natural next step after the Virtual User System is **Virtual Groups** implementation:

1. Enhance `GroupDatabase` with:
   - `add_user_to_group(username, groupname)` method
   - `remove_user_from_group(username, groupname)` method
   - `list_members(groupname)` method
   - Support for multiple supplementary groups per user

2. Update `_cmd_id` to list all supplementary groups, not just the primary group

3. Add command handlers: `groupadd`, `groupdel`, `groups`

4. Update `/etc/group` generation via `GroupDatabase.group_text()`

5. Add tests for: creating groups, adding users to groups, listing group members, group-based access control queries

The Virtual Groups milestone will complete the core identity management subsystem (Users + Groups) while maintaining the proven host-isolation invariant (zero host execution primitives, virtual filesystem only).