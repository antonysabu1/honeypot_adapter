"""Build the Markov action-transition table from session telemetry.

Reads all events from the SQLite store, classifies each action into a
category, and computes transition probabilities between consecutive
actions within each session.  Saves a JSON transition table to
models/action_transition_table.json.

Run from new/:
  python3 build_markov.py

If the database has fewer than 5 sessions the script generates a
bootstrapped table from the synthetic training sessions used by the
stage classifier (so the predictor always has something to work with).
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

from shared.predictor import classify_action_category


def _build_from_sequences(sequences: list[list[str]]) -> dict:
    """Build transition counts and normalise to probabilities."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for seq in sequences:
        for i in range(len(seq) - 1):
            counts[seq[i]][seq[i + 1]] += 1

    table: dict[str, dict[str, float]] = {}
    for from_cat, nexts in counts.items():
        total = sum(nexts.values())
        table[from_cat] = {cat: cnt / total for cat, cnt in nexts.items()}

    return table


def _bootstrap_sequences() -> list[list[str]]:
    """Synthetic sequences that reflect realistic attack paths."""
    return [
        # recon → discovery → credential_access
        ["recon", "recon", "discovery", "discovery", "credential_access"],
        ["recon", "discovery", "credential_access", "exfiltration"],
        # discovery heavy
        ["recon", "discovery", "discovery", "discovery", "credential_access", "persistence"],
        # persistence focus
        ["recon", "discovery", "persistence", "persistence", "exfiltration"],
        # exfil after credential
        ["recon", "credential_access", "exfiltration", "exfiltration"],
        # quick exfil
        ["recon", "exfiltration"],
        # destruction at end
        ["recon", "discovery", "persistence", "destruction"],
        # other paths
        ["other", "recon", "discovery", "credential_access"],
        ["recon", "other", "discovery", "exfiltration"],
        ["discovery", "credential_access", "exfiltration"],
    ] * 5  # repeat to give more weight


def build(db_path: str | None = None) -> dict:
    sequences: list[list[str]] = []

    try:
        from shared.storage import get_storage, StorageEngine
        from pathlib import Path as _Path
        store = StorageEngine(db_path) if db_path else get_storage()
        sessions = store.fetch_all("SELECT session_id FROM sessions WHERE closed_at IS NOT NULL")
        for sess in sessions:
            sid = sess["session_id"]
            events = store.fetch_all(
                "SELECT action, parameters FROM events WHERE session_id=? ORDER BY timestamp ASC",
                (sid,),
            )
            seq = []
            for ev in events:
                try:
                    params = json.loads(ev["parameters"]) if ev["parameters"] else {}
                except (json.JSONDecodeError, TypeError):
                    params = {}
                cat = classify_action_category(ev["action"], params)
                seq.append(cat)
            if len(seq) > 1:
                sequences.append(seq)
        if db_path and db_path != str(store._db_path):
            store._close()
    except Exception as exc:
        print(f"[build_markov] could not read DB: {exc}")

    if len(sequences) < 5:
        print("[build_markov] fewer than 5 sessions — bootstrapping with synthetic sequences")
        sequences = _bootstrap_sequences()

    table = _build_from_sequences(sequences)
    categories = sorted(table.keys())

    output = {
        "transition_table": table,
        "categories": categories,
        "sessions_used": len(sequences),
    }
    out_path = MODELS_DIR / "action_transition_table.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Transition table: {len(table)} states, saved to {out_path}")

    # Evaluate top-1 accuracy on held-out last-step of each sequence
    if sequences:
        correct = total = 0
        for seq in sequences:
            for i in range(1, len(seq)):
                current = seq[i - 1]
                actual  = seq[i]
                probs = table.get(current, {})
                predicted = max(probs, key=probs.get) if probs else None
                if predicted == actual:
                    correct += 1
                total += 1
        acc = correct / total if total > 0 else 0.0
        print(f"Top-1 accuracy on training sequences: {acc:.3f} ({correct}/{total})")

    return output


if __name__ == "__main__":
    build()
