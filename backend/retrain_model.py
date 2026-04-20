"""
retrain_model.py — Periodic Model Retraining Pipeline
======================================================
Run this script manually or via a cron job to retrain the fraud model
on accumulated labeled transaction data from the live database.

Usage:
  cd safepay/backend
  python retrain_model.py

What it does:
  1. Loads all labeled transactions from the DB
  2. Generates synthetic negatives if data is sparse (cold-start fix)
  3. Engineers features from raw transaction data
  4. Trains XGBoost (falls back to RandomForest if XGBoost unavailable)
  5. Evaluates on a held-out test set (prints precision/recall/AUC)
  6. Saves fraud_model.pkl and feature_schema.pkl (atomically)
  7. Archives the old model with a timestamp

Schedule suggestion (crontab):
  0 3 * * * cd /path/to/safepay/backend && python retrain_model.py >> retrain.log 2>&1
"""

import os
import sys
import sqlite3
import hashlib
import logging
import datetime
import shutil

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble        import RandomForestClassifier
from sklearn.metrics         import (
    classification_report, roc_auc_score,
    precision_score, recall_score, f1_score
)
from sklearn.preprocessing   import StandardScaler

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
)
log = logging.getLogger("retrain")

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "safepay.db")
MODEL_PATH  = os.path.join(BASE_DIR, "fraud_model.pkl")
SCHEMA_PATH = os.path.join(BASE_DIR, "feature_schema.pkl")
ARCHIVE_DIR = os.path.join(BASE_DIR, "model_archive")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

# ── Minimum rows required to retrain ─────────────────────────────────────────
MIN_ROWS = 50   # lower for demo; raise to 500+ in production


# ── Step 1: Load data from DB ─────────────────────────────────────────────────
def load_transactions() -> pd.DataFrame:
    """
    Load all transactions from SQLite and convert to a feature DataFrame.
    'blocked' and 'suspicious' transactions are treated as fraud=1.
    'success' transactions are fraud=0.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        """SELECT
             amount, status, risk_score, ml_score, rule_score,
             device_hash, location_lat, location_lon,
             created_at, username, recipient
           FROM transactions
           ORDER BY created_at"""
    ).fetchall()
    conn.close()

    records = []
    for r in rows:
        records.append({
            "amount":       float(r["amount"] or 0),
            "risk_score":   float(r["risk_score"] or 0),
            "ml_score":     float(r["ml_score"] or 0),
            "rule_score":   float(r["rule_score"] or 0),
            "has_location": 1 if r["location_lat"] else 0,
            "hour_utc":     _parse_hour(r["created_at"]),
            "is_night":     1 if _parse_hour(r["created_at"]) in range(0, 5) else 0,
            "device_hash":  r["device_hash"] or "",
            "username":     r["username"] or "",
            "created_at":   r["created_at"] or "",
            "label":        1 if r["status"] in ("blocked", "suspicious") else 0,
        })

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df = df.sort_values("created_at").reset_index(drop=True)
    return df


def _parse_hour(ts: str | None) -> int:
    if not ts:
        return 12
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "")).hour
    except Exception:
        return 12


# ── Step 2: Feature engineering ───────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build ML features from raw transaction rows.
    All features must be numeric (model requirement).
    """
    # Time since last transaction per user (in seconds)
    df["ts_epoch"] = pd.to_datetime(df["created_at"], errors="coerce").astype("int64") // 1e9

    df["time_since_last_txn"] = (
        df.groupby("username")["ts_epoch"]
          .diff()
          .fillna(999999)
          .clip(upper=999999)
    )

    # Transaction frequency per user (rolling count in last N rows)
    df["user_txn_count"] = (
        df.groupby("username").cumcount()
    )

    # Amount z-score per user
    user_stats = (
        df.groupby("username")["amount"]
          .agg(["mean", "std"])
          .rename(columns={"mean": "user_avg", "std": "user_std"})
          .reset_index()
    )
    df = df.merge(user_stats, on="username", how="left")
    df["user_std"]    = df["user_std"].fillna(1).replace(0, 1)
    df["amount_zscore"] = (df["amount"] - df["user_avg"]) / df["user_std"]

    # Device novelty: 1 if device_hash changes between consecutive txns per user
    df["device_changed"] = (
        df.groupby("username")["device_hash"]
          .transform(lambda s: s != s.shift(1))
          .fillna(0)
          .astype(int)
    )

    # Recipient novelty: 1 if recipient is new for this user
    # (implemented via simple hash comparison — good enough for ML)
    df["recipient_hash"] = df.get("recipient", pd.Series([""] * len(df))).fillna("").apply(
        lambda x: int(hashlib.md5(x.encode()).hexdigest()[:4], 16)
    )

    feature_cols = [
        "amount",
        "amount_zscore",
        "time_since_last_txn",
        "user_txn_count",
        "hour_utc",
        "is_night",
        "has_location",
        "device_changed",
        "recipient_hash",
        "rule_score",          # carry-over from rule engine (rich signal)
    ]

    # Fill any remaining NaN
    X = df[feature_cols].fillna(0).astype(float)
    y = df["label"].astype(int)

    return X, y, feature_cols


# ── Step 3: Synthetic data augmentation (cold-start) ──────────────────────────
def augment_with_synthetic(X: pd.DataFrame, y: pd.Series,
                            target_rows: int = 300) -> tuple:
    """
    When live data is sparse, add synthetic rows so the model has
    enough examples to learn from.

    Fraud patterns synthesised:
      - Very high amounts + night hour
      - High velocity (low time_since_last_txn)
      - Device change + new recipient

    This is deterministic (fixed seed) for reproducibility.
    """
    rng = np.random.default_rng(42)
    n_real = len(X)

    if n_real >= target_rows:
        log.info("Sufficient real data (%d rows) — skipping augmentation", n_real)
        return X, y

    n_synth = target_rows - n_real
    log.info("Adding %d synthetic rows to reach %d total", n_synth, target_rows)

    # Split synthetic into ~40% fraud, 60% legit
    n_fraud  = int(n_synth * 0.4)
    n_legit  = n_synth - n_fraud

    cols = X.columns.tolist()

    # Synthetic fraud
    fraud_rows = {
        "amount":              rng.uniform(50_000, 100_000, n_fraud),
        "amount_zscore":       rng.uniform(4, 10, n_fraud),
        "time_since_last_txn": rng.uniform(1, 300, n_fraud),
        "user_txn_count":      rng.integers(5, 20, n_fraud),
        "hour_utc":            rng.integers(0, 4, n_fraud),
        "is_night":            np.ones(n_fraud),
        "has_location":        rng.integers(0, 2, n_fraud),
        "device_changed":      np.ones(n_fraud),
        "recipient_hash":      rng.integers(0, 65536, n_fraud),
        "rule_score":          rng.uniform(50, 100, n_fraud),
    }

    # Synthetic legit
    legit_rows = {
        "amount":              rng.uniform(100, 5_000, n_legit),
        "amount_zscore":       rng.uniform(-1, 1, n_legit),
        "time_since_last_txn": rng.uniform(3600, 86400, n_legit),
        "user_txn_count":      rng.integers(0, 5, n_legit),
        "hour_utc":            rng.integers(8, 22, n_legit),
        "is_night":            np.zeros(n_legit),
        "has_location":        np.ones(n_legit),
        "device_changed":      np.zeros(n_legit),
        "recipient_hash":      rng.integers(0, 65536, n_legit),
        "rule_score":          rng.uniform(0, 20, n_legit),
    }

    df_fraud = pd.DataFrame(fraud_rows)[cols]
    df_legit = pd.DataFrame(legit_rows)[cols]

    X_aug = pd.concat([X, df_fraud, df_legit], ignore_index=True)
    y_aug = pd.concat([
        y,
        pd.Series(np.ones(n_fraud, dtype=int)),
        pd.Series(np.zeros(n_legit, dtype=int)),
    ], ignore_index=True)

    return X_aug, y_aug


# ── Step 4: Train model ────────────────────────────────────────────────────────
def train_model(X: pd.DataFrame, y: pd.Series):
    """
    Train XGBoost if available, otherwise RandomForest.
    Returns (model, feature_names).
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── Try XGBoost ───────────────────────────────────────────────────────────
    try:
        from xgboost import XGBClassifier  # type: ignore
        model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=len(y_train[y_train == 0]) / max(len(y_train[y_train == 1]), 1),
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            verbosity=0,
        )
        model_name = "XGBoost"
    except ImportError:
        log.warning("XGBoost not installed — using RandomForest")
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        model_name = "RandomForest"

    log.info("Training %s on %d samples (%d fraud, %d legit)…",
             model_name, len(X_train),
             int(y_train.sum()), int((y_train == 0).sum()))

    model.fit(X_train, y_train)

    # ── Evaluation ────────────────────────────────────────────────────────────
    y_prob  = model.predict_proba(X_test)[:, 1]
    y_pred  = (y_prob >= 0.5).astype(int)

    auc       = roc_auc_score(y_test, y_prob)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)

    log.info("── Evaluation Results ──────────────────────────────")
    log.info("  AUC-ROC:   %.4f", auc)
    log.info("  Precision: %.4f", precision)
    log.info("  Recall:    %.4f", recall)
    log.info("  F1 Score:  %.4f", f1)
    log.info("────────────────────────────────────────────────────")
    log.info("\n%s", classification_report(y_test, y_pred,
                                           target_names=["Legit", "Fraud"],
                                           zero_division=0))

    return model, X.columns.tolist()


# ── Step 5: Save model ────────────────────────────────────────────────────────
def save_model(model, feature_names: list):
    """
    Atomically replace fraud_model.pkl and feature_schema.pkl.
    Archive the old model with a timestamp before overwriting.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Archive old model if it exists
    if os.path.exists(MODEL_PATH):
        archive_path = os.path.join(ARCHIVE_DIR, f"fraud_model_{timestamp}.pkl")
        shutil.copy2(MODEL_PATH, archive_path)
        log.info("Archived old model to %s", archive_path)

    # Write to temp files then rename (atomic on POSIX)
    tmp_model  = MODEL_PATH  + ".tmp"
    tmp_schema = SCHEMA_PATH + ".tmp"

    joblib.dump(model,        tmp_model)
    joblib.dump(feature_names, tmp_schema)

    os.replace(tmp_model,  MODEL_PATH)
    os.replace(tmp_schema, SCHEMA_PATH)

    log.info("✅ Saved new model → %s", MODEL_PATH)
    log.info("✅ Saved feature schema (%d features) → %s",
             len(feature_names), SCHEMA_PATH)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("SafePay Model Retraining Pipeline")
    log.info("Started at %s UTC", datetime.datetime.utcnow().isoformat())
    log.info("=" * 60)

    # 1. Load
    df = load_transactions()
    if df.empty:
        log.warning("No transactions found in DB. Generating fully synthetic dataset.")
        # Create a minimal skeleton df so augmentation can run
        df = pd.DataFrame(columns=[
            "amount", "risk_score", "ml_score", "rule_score",
            "has_location", "hour_utc", "is_night", "device_hash",
            "username", "created_at", "label", "ts_epoch",
            "time_since_last_txn", "user_txn_count",
        ])

    log.info("Loaded %d transactions from DB  (%d fraud, %d legit)",
             len(df),
             int(df["label"].sum()) if "label" in df.columns else 0,
             int((df["label"] == 0).sum()) if "label" in df.columns else 0)

    # 2. Feature engineering
    if len(df) >= 2:
        X, y, feature_cols = engineer_features(df)
    else:
        # Build empty frames with correct columns so augmentation works
        feature_cols = [
            "amount", "amount_zscore", "time_since_last_txn",
            "user_txn_count", "hour_utc", "is_night", "has_location",
            "device_changed", "recipient_hash", "rule_score",
        ]
        X = pd.DataFrame(columns=feature_cols)
        y = pd.Series(dtype=int)

    # 3. Augment if needed
    X, y = augment_with_synthetic(X, y, target_rows=500)

    if len(X) < MIN_ROWS:
        log.error("Still fewer than %d rows after augmentation (%d). Aborting.", MIN_ROWS, len(X))
        sys.exit(1)

    # 4. Train
    model, feature_names = train_model(X, y)

    # 5. Save
    save_model(model, feature_names)

    log.info("Retraining complete.")


if __name__ == "__main__":
    main()
