import json
import os
from pathlib import Path

from shared.events import CONTRACT_KEYS, mitre_of

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "honeypot.jsonl"

# The adapter contract: exactly these eleven top-level fields. MITRE ATT&CK
# metadata lives nested under raw_metadata["mitre"], never as a top-level key.
REQUIRED_KEYS = CONTRACT_KEYS


def _max_log_size_bytes() -> int:
    """Return the configured maximum log size in bytes."""
    from shared.config import get
    mb = get("limits.max_log_size_mb", 100)
    return mb * 1024 * 1024


def _prune_log() -> None:
    """Trim the log file if it exceeds the configured maximum size.

    Uses an atomic write (write to temp file, then rename) so that a
    power failure or signal during pruning never leaves the log in an
    inconsistent state.  Malformed lines are skipped rather than
    causing the entire prune to fail.
    """
    max_bytes = _max_log_size_bytes()
    if not LOG_FILE.exists():
        return
    size = LOG_FILE.stat().st_size
    if size <= max_bytes:
        return
    # Read all lines, keep only the most recent ones that fit under the limit
    good: list[str] = []
    total = 0
    with LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            try:
                evt = json.loads(line)
                # Verify minimum structure; skip truly corrupt lines.
                for k in ("event_id", "timestamp", "action"):
                    if k not in evt:
                        raise ValueError("missing required field")
            except (json.JSONDecodeError, ValueError):
                # Corrupt line — drop it to protect the overall log integrity.
                continue
            line_bytes = len(line.encode("utf-8")) + 1  # +1 for "\n"
            if total + line_bytes > max_bytes:
                break
            good.append(line + "\n")
            total += line_bytes
    # Atomic rewrite: write to a temp file in the same directory, then rename.
    # This prevents a crash / power-loss from leaving the log truncated or
    # empty (the original file is only replaced after the new content is fully
    # written and flushed).
    import tempfile
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(LOG_FILE.parent), suffix=".jsonl.tmp"
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp:
            tmp.writelines(good)
        os.replace(tmp_path, str(LOG_FILE))
    except BaseException:
        # If anything goes wrong, discard the temp file; the original log
        # remains untouched so no data is lost.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def log_event(event_dict: dict) -> None:
    missing = [key for key in REQUIRED_KEYS if key not in event_dict]
    if missing:
        raise ValueError(f"log_event: missing required keys: {', '.join(missing)}")
    extra = [key for key in event_dict if key not in REQUIRED_KEYS]
    if extra:
        raise ValueError(
            f"log_event: unauthorized top-level keys: {', '.join(sorted(extra))}"
        )

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict, ensure_ascii=False) + "\n")
    except (OSError, BrokenPipeError) as exc:
        # Telemetry failure must never execute attacker code or mutate
        # VirtualOS state; we simply log to stderr and return so the
        # honeypot continues operating without telemetry for this event.
        print(f"telemetry write failure: {exc}", flush=True)
        return

    # Enforce maximum log size (atomic prune; cannot raise)
    try:
        _prune_log()
    except Exception:
        # Prune failure must also never mask a security event; ignore and
        # keep the running honeypot functional.
        print("telemetry prune failure", flush=True)

    # Dual write: also persist to SQLite. Best-effort \u2014 never raises.
    try:
        _write_to_storage(event_dict)
    except Exception:
        pass

    # Update attack-progression graph for this session. Best-effort.
    try:
        _update_attack_graph(event_dict)
    except Exception:
        pass

    print(
        f"[{str(event_dict['protocol']).upper()}] "
        f"{event_dict['source_ip']} \u2192 action: {event_dict['action']}"
    )


def _update_attack_graph(event_dict: dict) -> None:
    from shared.attack_graph import evaluate_event
    session_id = event_dict.get("session_id", "")
    action = event_dict.get("action", "")
    params = event_dict.get("parameters") or {}
    evaluate_event(session_id, action, params)


def _write_to_storage(event_dict: dict) -> None:
    """Write one event to the SQLite store (best-effort, called from log_event)."""
    import shared.storage as storage_mod
    # Redirect DB to the same directory as LOG_FILE so tests stay isolated.
    db_path = Path(LOG_FILE).parent / "honeypot.db"
    if storage_mod.DB_FILE != db_path:
        storage_mod.DB_FILE = db_path
        storage_mod.close_storage()
    store = storage_mod.get_storage()

    mitre = mitre_of(event_dict)
    store.insert_event(
        event_id=event_dict.get("event_id"),
        session_id=event_dict.get("session_id"),
        protocol=event_dict.get("protocol", ""),
        action=event_dict.get("action", ""),
        parameters=event_dict.get("parameters"),
        response_type=event_dict.get("response_type", ""),
        status=str(event_dict.get("response_status", "0")),
        mitre_attack_id=mitre.get("mitre_attack_id"),
        mitre_technique_name=mitre.get("mitre_technique_name"),
        mitre_tactic=mitre.get("mitre_tactic"),
        mitre_technique_name_secondary=mitre.get("mitre_technique_name_secondary"),
    )