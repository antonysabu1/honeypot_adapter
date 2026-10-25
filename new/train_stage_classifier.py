"""Train the attack-stage and intent classifiers for SSH/Telnet sessions.

Generates synthetic training data that reflects realistic attacker
behaviour patterns, then trains a Decision Tree (primary) and Random
Forest (secondary) classifier for two labels:

  stage   recon | discovery | credential_access | persistence | exfiltration
  intent  passive_scan | active_exploit | data_theft | backdoor

Run from new/:
  python3 train_stage_classifier.py

Writes to new/models/ (created if absent).
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Install scikit-learn and joblib if missing
try:
    import joblib
    import numpy as np
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score
except ImportError:
    print("Install scikit-learn and joblib: pip install scikit-learn joblib numpy")
    sys.exit(1)

from shared.features import FEATURE_NAMES

MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

RANDOM_STATE = 42
random.seed(RANDOM_STATE)
np.random.seed(RANDOM_STATE)

# ---------------------------------------------------------------------------
# Synthetic training data
# Each tuple: (feature_dict, stage_label, intent_label)
# Feature dict maps FEATURE_NAMES keys to values.
# ---------------------------------------------------------------------------

def _feat(**kw) -> list[float]:
    """Build a feature vector; unset keys default to 0.0."""
    d = {n: 0.0 for n in FEATURE_NAMES}
    d.update({k: float(v) for k, v in kw.items()})
    return [d[n] for n in FEATURE_NAMES]


def _gen_samples(n: int = 200) -> tuple[list, list, list]:
    X, y_stage, y_intent = [], [], []

    # --- Stage: recon (whoami, id, uname, hostname) ---
    for _ in range(n // 5):
        X.append(_feat(
            command_count=random.uniform(1, 8),
            command_rate=random.uniform(0.5, 5),
            distinct_commands=random.uniform(1, 5),
            error_ratio=random.uniform(0, 0.2),
            has_recon=1.0,
            session_duration_s=random.uniform(10, 120),
        ))
        y_stage.append("recon")
        y_intent.append("passive_scan")

    # --- Stage: discovery (find, ls, cat /etc/passwd, ps) ---
    for _ in range(n // 5):
        X.append(_feat(
            command_count=random.uniform(5, 30),
            command_rate=random.uniform(1, 10),
            distinct_commands=random.uniform(3, 10),
            error_ratio=random.uniform(0, 0.3),
            has_recon=random.choice([0.0, 1.0]),
            has_discovery=1.0,
            session_duration_s=random.uniform(30, 600),
        ))
        y_stage.append("discovery")
        y_intent.append("passive_scan")

    # --- Stage: credential_access ---
    for _ in range(n // 5):
        X.append(_feat(
            command_count=random.uniform(3, 20),
            command_rate=random.uniform(0.5, 8),
            distinct_commands=random.uniform(2, 8),
            error_ratio=random.uniform(0, 0.4),
            has_recon=1.0,
            has_discovery=random.choice([0.0, 1.0]),
            has_credential_access=1.0,
            has_lure_access=random.choice([0.0, 1.0]),
            session_duration_s=random.uniform(60, 900),
        ))
        y_stage.append("credential_access")
        y_intent.append("active_exploit")

    # --- Stage: persistence ---
    for _ in range(n // 5):
        X.append(_feat(
            command_count=random.uniform(10, 50),
            command_rate=random.uniform(1, 15),
            distinct_commands=random.uniform(5, 15),
            error_ratio=random.uniform(0, 0.2),
            has_recon=1.0,
            has_discovery=1.0,
            has_credential_access=random.choice([0.0, 1.0]),
            has_persistence=1.0,
            session_duration_s=random.uniform(120, 1800),
        ))
        y_stage.append("persistence")
        y_intent.append("backdoor")

    # --- Stage: exfiltration ---
    for _ in range(n // 5):
        X.append(_feat(
            command_count=random.uniform(5, 40),
            command_rate=random.uniform(0.5, 10),
            distinct_commands=random.uniform(3, 12),
            error_ratio=random.uniform(0, 0.2),
            has_recon=random.choice([0.0, 1.0]),
            has_discovery=1.0,
            has_credential_access=random.choice([0.0, 1.0]),
            has_lure_access=random.choice([0.0, 1.0]),
            has_exfil=1.0,
            session_duration_s=random.uniform(60, 1200),
        ))
        y_stage.append("exfiltration")
        y_intent.append("data_theft")

    return X, y_stage, y_intent


def train() -> None:
    X_list, y_stage, y_intent = _gen_samples(250)
    X = np.array(X_list)

    X_tr, X_te, ys_tr, ys_te, yi_tr, yi_te = train_test_split(
        X, y_stage, y_intent, test_size=0.2, random_state=RANDOM_STATE, stratify=y_stage
    )

    results = {}
    for label_name, y_tr, y_te in (("stage", ys_tr, ys_te), ("intent", yi_tr, yi_te)):
        dt = DecisionTreeClassifier(max_depth=5, random_state=RANDOM_STATE)
        dt.fit(X_tr, y_tr)
        dt_acc = accuracy_score(y_te, dt.predict(X_te))
        dt_f1  = f1_score(y_te, dt.predict(X_te), average="macro")

        rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=RANDOM_STATE)
        rf.fit(X_tr, y_tr)
        rf_acc = accuracy_score(y_te, rf.predict(X_te))
        rf_f1  = f1_score(y_te, rf.predict(X_te), average="macro")

        joblib.dump({"model": dt, "feature_names": FEATURE_NAMES},
                    MODELS_DIR / f"{label_name}_classifier.joblib")
        joblib.dump({"model": rf, "feature_names": FEATURE_NAMES},
                    MODELS_DIR / f"{label_name}_classifier_rf.joblib")

        results[label_name] = {"dt_acc": dt_acc, "dt_f1": dt_f1, "rf_acc": rf_acc, "rf_f1": rf_f1}
        print(f"{label_name}: DT acc={dt_acc:.3f} f1={dt_f1:.3f}  RF acc={rf_acc:.3f} f1={rf_f1:.3f}")

    (MODELS_DIR / "classifier_metrics.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(f"\nModels saved to {MODELS_DIR}")


if __name__ == "__main__":
    train()
