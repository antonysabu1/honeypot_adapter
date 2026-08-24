import json
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


def log_event(event_dict: dict) -> None:
    missing = [key for key in REQUIRED_KEYS if key not in event_dict]
    if missing:
        raise ValueError(f"log_event: missing required keys: {', '.join(missing)}")

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event_dict, ensure_ascii=False) + "\n")

    print(
        f"[{str(event_dict['protocol']).upper()}] "
        f"{event_dict['source_ip']} \u2192 action: {event_dict['action']}"
    )
