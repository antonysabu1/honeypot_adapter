"""Live attack-stage inference for SSH/Telnet sessions.

Loads the pre-trained classifiers from models/ and runs predictions
against a session's current feature vector.  Falls back gracefully when
models are missing or feature extraction fails — the honeypot continues
operating without predictions in that case.

Mirrors the HTTP honeypot's predictor.py, adapted for SSH/Telnet.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def predict_stage_intent(session_id: str, db_path: str | None = None) -> tuple[str | None, str | None, float]:
    """Predict the attack stage and intent for *session_id*.

    Returns (stage, intent, confidence).  Confidence is the minimum
    predicted-class probability across both models.  Returns
    (None, None, 0.0) when models are unavailable or extraction fails.
    """
    try:
        import joblib
        import numpy as np
    except ImportError:
        return (None, None, 0.0)

    stage_path  = MODELS_DIR / "stage_classifier.joblib"
    intent_path = MODELS_DIR / "intent_classifier.joblib"
    if not stage_path.exists() or not intent_path.exists():
        logger.warning("Stage/intent model files missing — skipping prediction")
        return (None, None, 0.0)

    try:
        from shared.features import extract_session_features
        features = extract_session_features(session_id, db_path=db_path)
    except Exception as exc:
        logger.warning("Feature extraction failed for %s: %s", session_id, exc)
        return (None, None, 0.0)

    try:
        X = np.array([features])
        stage_model  = joblib.load(stage_path)["model"]
        intent_model = joblib.load(intent_path)["model"]

        stage  = stage_model.predict(X)[0]
        intent = intent_model.predict(X)[0]

        stage_proba  = float(np.max(stage_model.predict_proba(X)[0]))
        intent_proba = float(np.max(intent_model.predict_proba(X)[0]))
        confidence   = min(stage_proba, intent_proba)

        return (stage, intent, confidence)
    except Exception as exc:
        logger.warning("Model prediction failed: %s", exc)
        return (None, None, 0.0)


def detect_anomaly(session_id: str, db_path: str | None = None) -> tuple[bool, float]:
    """Detect whether *session_id*'s behaviour is anomalous.

    Returns (is_anomalous, anomaly_score).  Returns (False, 0.0) when the
    model is missing or extraction fails.
    """
    try:
        import joblib
        import numpy as np
    except ImportError:
        return (False, 0.0)

    model_path = MODELS_DIR / "anomaly_detector.joblib"
    if not model_path.exists():
        return (False, 0.0)

    try:
        from shared.features import extract_session_features
        features = extract_session_features(session_id, db_path=db_path)
    except Exception as exc:
        logger.warning("Feature extraction failed for anomaly %s: %s", session_id, exc)
        return (False, 0.0)

    try:
        X = np.array([features])
        data = joblib.load(model_path)
        iso   = data["model"]
        scaler = data["scaler"]
        X_scaled = scaler.transform(X)
        score = float(iso.score_samples(X_scaled)[0])
        is_anomalous = bool(iso.predict(X_scaled)[0] == -1)
        return (is_anomalous, score)
    except Exception as exc:
        logger.warning("Anomaly detection failed: %s", exc)
        return (False, 0.0)


def predict_next_categories(session_id: str, top_k: int = 3, db_path: str | None = None) -> list[str]:
    """Predict the most likely next action categories for *session_id*.

    Loads the Markov transition table, determines the session's most
    recent action category, and returns the top-k most probable next
    categories.  Returns an empty list when the table is missing.
    """
    table_path = MODELS_DIR / "action_transition_table.json"
    if not table_path.exists():
        return []

    try:
        import json as _json
        data = _json.loads(table_path.read_text(encoding="utf-8"))
        transition_table = data["transition_table"]
        categories = data["categories"]
    except Exception as exc:
        logger.warning("Failed to load transition table: %s", exc)
        return []

    try:
        from shared.storage import get_storage, StorageEngine
        from pathlib import Path as _Path

        store = StorageEngine(db_path) if db_path else get_storage()
        row = store.fetch_one(
            "SELECT action, parameters FROM events WHERE session_id=? ORDER BY timestamp DESC LIMIT 1",
            (session_id,),
        )
        if db_path:
            store._close()

        if row is None:
            return categories[:top_k]

        try:
            import json as _j
            params = _j.loads(row["parameters"]) if row["parameters"] else {}
        except Exception:
            params = {}

        current_cat = classify_action_category(row["action"], params)
        probs = transition_table.get(current_cat, {})
        if not probs:
            return categories[:top_k]

        return sorted(probs, key=probs.__getitem__, reverse=True)[:top_k]
    except Exception as exc:
        logger.warning("Markov prediction failed: %s", exc)
        return categories[:top_k] if categories else []


def classify_action_category(action: str, params: dict | None = None) -> str:
    """Map a command action string to one of the Markov action categories."""
    name = (params or {}).get("name", action.split()[0] if action else "")
    _RECON    = {"whoami", "id", "uname", "hostname", "w", "who", "last", "uptime"}
    _DISCOVERY= {"find", "locate", "ls", "cat", "less", "more", "grep", "ps",
                 "netstat", "ss", "df", "du", "env", "printenv", "head", "tail"}
    _CRED     = {"ssh-keygen", "ssh", "su", "sudo"}
    _PERSIST  = {"crontab", "useradd", "adduser", "systemctl", "service"}
    _EXFIL    = {"curl", "wget", "scp", "sftp", "rsync", "nc", "ncat"}
    _DESTROY  = {"rm", "shred", "dd", "mkfs"}

    if name in _RECON:
        return "recon"
    if name in _DISCOVERY:
        return "discovery"
    if name in _CRED:
        return "credential_access"
    if name in _PERSIST:
        return "persistence"
    if name in _EXFIL:
        return "exfiltration"
    if name in _DESTROY:
        return "destruction"
    # Lure file reads
    args = " ".join(str(a) for a in (params or {}).get("args", []))
    lure_paths = (".aws/credentials", ".ssh/id_rsa", "config.php", "my.cnf", ".bash_history")
    if any(p in args for p in lure_paths):
        return "credential_access"
    return "other"
