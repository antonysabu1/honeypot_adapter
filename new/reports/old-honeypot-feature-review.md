# Feature Port Review — `old/simplehoneypot` → `new/`

**Date:** 2026-09-10 (rev 2 — command counts re-verified by script)
**Scope:** Feature inventory of the legacy honeypot (`old/simplehoneypot/`, ~6,700 LOC)
with porting recommendations for the new adapter (`new/`).

> **Verification note (rev 2):** every symbol, line number, and count below was
> re-checked against the code on 2026-09-10 (see Appendix A for the exact
> counting commands). Rev 1's "~200 commands" and "~12 commands" were wrong;
> the precise figures are **160** and **20**.

---

## Old honeypot inventory (what it has)

| Area | Module | Notes |
|---|---|---|
| SSH shell engine | `ssh_honeypot.py` (4,168 LOC) | **160** emulated command names → **118** handlers, Cowrie-style VFS, timing, tab completion |
| Telnet honeypot | `telnet_honeypot.py` | ThreadPoolExecutor (50 workers), SO_KEEPALIVE, password masking, signal handling |
| HTTP honeypot | `http_honeypot.py` | Siemens/ICS admin panel, login capture, `/api/status`, exploit scan |
| Management API | `api_server.py` | Loopback REST: sessions/stats/attackers/health, key auth |
| Static dashboard | `dashboard.html` | Offline drag-and-drop analysis of JSONL logs (MITRE, per-protocol) |
| Deception persona | `deception_persona.py`, `generate_persona.py` | Single identity source (hostname/OS/kernel/user), env-overridable, Kali persona "albin" |
| Fake network | `fake_network.py` | Fake /24 (router/NAS/camera/printer/IoT), ARP, ping, port scan, sweep |
| Exploit capture | `vuln_emulation.py` | Log4Shell, traversal, cmd-injection, SQLi, XSS detection + "as-if-exploited" replies |
| Honeytokens | `v2-staging/honeytokens.py` | Decoy creds/keys/dumps seeded in VFS; read detection with MITRE + severity |
| VFS | `HoneyPotFilesystem` in `ssh_honeypot.py` | Symlinks, modes, uid/gid, /proc, /etc, /var/log, per-session deepcopy |
| Logging | `SessionLogger` (`ssh_honeypot.py:246`) | SIGKILL-safe per-event append, batched SIEM shipping (Bearer token) |
| TTY replay | `TTYLog` (`ssh_honeypot.py:159`) | Cowrie-compatible binary ttylog, input SHA-256 hash, replay scripts |
| Rate limit | `RateLimiter` (`ssh_honeypot.py:3553`) | Per-IP sliding window, bounded memory (5,000 keys) |
| GeoIP | `_get_geoip` (`ssh_honeypot.py:3606`) | ip-api.com lookup, TTL cache |
| Config | `honeypot_config.json` | Persona, network, logging, SIEM, alerts webhook, rate limits |
| Ops | `Dockerfile`, `docker-compose.yml`, `etc/`, `scripts/` | Read-only rootfs, seccomp, HEALTHCHECK, validation, abuseipdb reporting |
| Staged (v2) | `v2-staging/` | FTP, SMB, MySQL, Redis, MQTT, Modbus, S7comm, DNP3, DNS, RDP, alert manager, log shipper, ML detection |

---

## New adapter current state (gaps)

| Area | Status |
|---|---|
| Protocols | SSH (2222) + Telnet (2323) only; no HTTP/ICS panel |
| Shell commands | **20 command names** across 19 branches in `shared/response_engine.py`: `ls`*, `cat`*, `pwd`, `whoami`, `uname`, `cd`, `exit`, `echo`, `id`, `date`, `ps`, `df`, `ifconfig`, `history`, `last`, `w`, `uptime`, `hostname`, `apt`/`apt-get` — everything else → `command not found` (127) |
| Filesystem | Static nested dict; no modes, symlinks, /proc, mutations |
| Honeytokens / fake network / exploit capture / TTY replay / SIEM / rate limit / GeoIP | None |
| Telnet password | Echoed in cleartext (old masks with `*`) |
| Auth | Accepts any credentials instantly (old rejects until persona user + password, logging failed tries) |
| MITRE | `shared/mitre.py` — argument-aware, confidence-scored, ICS tokens; **coarser on ICS than old** (see §5) |
| Telnet IAC | **Already better than old** — handles split subnegotiations |

\* `ls` is matched by raw prefix (`lsblk`, `lsof` would hit it); `cat` requires
a trailing space, so bare `cat` falls through to `command not found`. Both are
quirk of the current matcher, not a design choice.

---

## 1. Porting map — Tier 1 (realism/detection, recommended first)

| Feature | Old module : symbol | Target (new/) | Adaptation note |
|---|---|---|---|
| Command table | `ssh_honeypot.py` : `ShellEngine._cmd_*` (e.g. `_cmd_ifconfig`:2524, `_cmd_apt`:2628, `_cmd_python`:2966) | `shared/response_engine.py` | **Not a drop-in.** Old handlers are `(self, args, stdin_data)` methods on `ShellEngine` and depend on `self.fs`, `self.env`, `self.pwd`, `self.oldpwd`, `self.last_exit_code`, `self._sim_delay`, `self._check_honeytoken`. The new contract is the pure `decide_response(...) -> ResponsePlan`; port as pure functions (output builders), thread `fs`/`cwd` through `parameters` |
| Zero-egress tools | `ssh_honeypot.py` : `_cmd_wget` (2693; also serves `curl`) | `shared/response_engine.py` | Same adaptation as above; keep the guarantee: fake transcript, capture URL, marker file in VFS only — never real egress |
| Honeytokens | `v2-staging/honeytokens.py` : `HONEYTOKENS` registry; `ssh_honeypot.py` : `_seed_honeytokens` (1271), `_check_honeytoken` (1398) | `shared/filesystem.py` (seed) + `shared/response_engine.py` (read hook) | Registry is portable as-is; the read hook must move into the new `cat`/`head`/`grep` path; old hooks write via old `session_logger`/`log_event` — re-point at `shared/logger.py` |
| Fake network | `fake_network.py` : `FAKE_HOSTS`, `neighbors`, `arp_table`, `ping`, `port_scan`, `sweep` | new `shared/fake_network.py`, wired into `response_engine` `ping`/`ifconfig`/`arp`/`nmap` | Module is stdlib-only and self-contained; replace `from service_base import log_event, new_session_id` with `shared.logger`/`shared.session` (the old module logs `fake_host_scan` events) |

## 2. Porting map — Tier 2 (telemetry/ops)

| Feature | Old module : symbol | Target (new/) | Adaptation note |
|---|---|---|---|
| TTY replay | `ssh_honeypot.py` : `TTYLog` (159) | new `shared/ttylog.py`; hooks in both adapters | Struct-format code is portable verbatim (Cowrie `ttylog/convert.py` compatible); old rotation config (`max_tty_age_days`, `max_tty_size_mb`) comes from `honeypot_config.json` — new has no config layer yet |
| SIEM shipping | `ssh_honeypot.py` : `SessionLogger._ship_batch`/`_ship_to_siem` (279/287) | `shared/logger.py` | Endpoint + Bearer token are config-driven; keep per-event disk append, ship in batches (no SIGKILL loss) |
| Rate limit | `ssh_honeypot.py` : `RateLimiter` (3553) | new `shared/ratelimit.py`; wire into `ssh_adapter/server.py` `check_auth_password` + telnet login | Class is standalone (thread-safe, bounded memory); drop-in |
| GeoIP | `ssh_honeypot.py` : `_get_geoip` (3606) | `shared/logger.py` enrichment | ~40 lines with TTL cache; call on auth events only |
| Failed-password realism | `ssh_honeypot.py` : `check_auth_password` (3737) | `ssh_adapter/server.py` + `telnet_adapter/session.py` | Old accepts only persona user + configured password and logs each failed try; needs persona config to exist first |
| Telnet password masking | `telnet_honeypot.py` : `recv_line(mask=True)` (101/187) | `telnet_adapter/session.py` `handle_data` | Smallest fix in the whole list: echo `*` (not the byte) while `self.state == "password"` |

## 3. Tier 3 — surface area (no map; low ambiguity)

- HTTP honeypot (Siemens/ICS panel) + credential capture — stdlib-only, ports in an afternoon.
- `vuln_emulation.py` exploit capture (Log4Shell/traversal/SQLi/XSS) — regexes + reply table are standalone; re-point `record()` at new `shared/logger.py`.
- Loopback management API + `dashboard.html` — **not a drop-in**: the dashboard uploads
  `sessions.jsonl`/`commands.log`/`ssh_honeypot.log` (old schemas), while new writes
  `logs/honeypot.jsonl` with a different schema. Port either the API with an adapter for
  the new event dict, or teach the dashboard's parser the new schema.
- Centralized persona module (`deception_persona.py`) — new adapter hardcodes Ubuntu strings in 4 files; persona module makes SSH banner, telnet banner, `uname`, `hostname`, `/etc/os-release` agree.

## 4. Tier 4 — only if containerizing

Docker hardening (read-only rootfs, seccomp, dropped caps, HEALTHCHECK, host-key volume); `validate_honeypot.py`; `daily_report.py`; abuseipdb reporting.

## 5. Do NOT port

- `ssh_honeypot.py` wholesale — lift command behaviors, not the 4k-line monolith.
- Old telnet IAC parsing — new handles split subnegotiations correctly; old skips 2 bytes.
- Old MITRE map *as-is*. Nuance: old `MITRE_ICS_TECHNIQUES` is **finer on ICS** —
  `modbus/plc/dnp3/bacnet/enetip/iec104/mqtt/snmp → T0731`, `hmi → T0815`,
  `opc/scada/sis → T0802`, `icsconfig → T0812` — while new `mitre.py` maps all
  ICS activity to flat `T0869`. New is stronger on confidence/secondary IDs and
  argument-aware ICS detection; the port should keep new's structure and adopt
  old's per-token ICS granularity, not the old lookup table.
- Instant-success auth design — reconsider per old v1.0.0 decision (realism vs catch-all).

---

## Appendix A — how the numbers were verified (2026-09-10)

```bash
# old: command names and handlers
grep -c 'def _cmd_' ssh_honeypot.py                       # 123 def lines
grep -oE 'def _cmd_[a-z_]+' ssh_honeypot.py | sort -u | wc -l   # 122 distinct
sed -n '3433,3494p' ssh_honeypot.py | grep -oE "'[a-zA-Z0-9._-]+':\s*'_cmd_" | wc -l   # 160 keys (_CMD_MAP, line 3432)
sed -n '3433,3494p' ssh_honeypot.py | grep -oE "'_cmd_[a-z_]+'" | sort -u | wc -l     # 118 distinct handlers referenced
# → 160 command names (120 primary + 40 aliases: htop→top, curl→wget, egrep→grep,
#   sha256sum/md5sum/sha1sum→checksum, apt-get→apt, vim/nano/pico→vi, ip→ifconfig, ...)
#   backed by 118 handlers; 4 defs unmapped (base, dnp, iec, not_found), _cmd_xargs defined twice.

# new: commands handled
grep -nE 'startswith\(|== "|in \(' shared/response_engine.py | grep -E 'command|base'  # 18 lines
# line 43 'action.strip().startswith("ls")' also matches → 19 branches, 20 names
# (apt/apt-get share one branch; ls/cat matched by prefix — see §gaps table footnote)
```

## Appendix B — file ownership for the eventual commit

- `new/reports/old-honeypot-feature-review.md` — this review (deliverable).
- `new/reports/functionality-report.md`, `new/reports/test-log.md` — pre-existing QA
  reports (2026-09-08), not part of this work; leave untouched.
- `.freebuff/` — agent metadata; gitignored (root `.gitignore`), never commit.