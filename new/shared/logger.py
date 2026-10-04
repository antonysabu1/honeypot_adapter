import json
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "honeypot.jsonl"

REQUIRED_KEYS = (
    "event_id",
    "timestamp",
    "protocol",
    "source_ip",
    "session_id",
    "action",
    "parameters",
    "raw_metadata",
    "session_source",
    "response_status",
    "response_type",
)


def _max_log_size_bytes() -> int:
    """Return the configured maximum log size in bytes."""
    from shared.config import get
    mb = get("limits.max_log_size_mb", 100)
    return mb * 1024 * 1024


def _prune_log() -> None:
    """Trim the log file if it exceeds the configured maximum size."""
    max_bytes = _max_log_size_bytes()
    if not LOG_FILE.exists():
        return
    size = LOG_FILE.stat().st_size
    if size <= max_bytes:
        return
    # Read all lines, keep only the most recent ones that fit under the limit
    with LOG_FILE.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    # Truncate from the front, keeping the most recent entries
    total = 0
    kept: list[str] = []
    for line in reversed(lines):
        total += len(line.encode("utf-8"))
        if total > max_bytes:
            break
        kept.append(line)
    kept.reverse()
    with LOG_FILE.open("w", encoding="utf-8") as f:
        f.writelines(kept)


def log_event(event_dict: dict) -> None:
    missing = [key for key in REQUIRED_KEYS if key not in event_dict]
    if missing:
        raise ValueError(f"log_event: missing required keys: {', '.join(missing)}")

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event_dict, ensure_ascii=False) + "\n")

    # Enforce maximum log size
    _prune_log()

    print(
        f"[{str(event_dict['protocol']).upper()}] "
        f"{event_dict['source_ip']} \u2192 action: {event_dict['action']}"
    )
