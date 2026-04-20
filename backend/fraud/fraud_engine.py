"""
fraud_engine.py — Hybrid Fraud Detection System
"""

import os
import logging
import datetime
from typing import NamedTuple

import numpy as np
import joblib

log = logging.getLogger("safepay.fraud")

BLOCK_THRESHOLD  = 75
HIGH_THRESHOLD   = 65
MEDIUM_THRESHOLD = 30

RULE_NEW_DEVICE     = 25
RULE_HIGH_VELOCITY  = 20
RULE_RAPID_FIRE     = 15
RULE_UNUSUAL_AMOUNT = 20
RULE_LARGE_AMOUNT   = 15
RULE_LATE_NIGHT     = 10
RULE_FAILED_RECENT  = 10

ML_WEIGHT   = 0.70
RULE_WEIGHT = 0.30

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH   = os.path.join(BASE_DIR, "fraud_model.pkl")
SCHEMA_PATH  = os.path.join(BASE_DIR, "feature_schema.pkl")

try:
    _model          = joblib.load(MODEL_PATH)
    _feature_schema = joblib.load(SCHEMA_PATH)
    ML_AVAILABLE    = True
    log.info("Fraud model loaded — %d features", len(_feature_schema))
except Exception as exc:
    log.warning("Could not load fraud model (%s). Using rule-based fallback.", exc)
    _model          = None
    _feature_schema = []
    ML_AVAILABLE    = False


class FraudResult(NamedTuple):
    risk_score:   float
    ml_score:     float
    rule_score:   float
    risk_level:   str
    risk_flags:   list
    should_block: bool
    require_otp:  bool


def _ml_score(payload: dict) -> float:
    if not ML_AVAILABLE or not _feature_schema:
        return 0.0
    row = np.zeros((1, len(_feature_schema)))
    for i, feat in enumerate(_feature_schema):
        val = payload.get(feat, 0)
        try:
            row[0, i] = float(val) if val not in (None, "", "NaN") else 0.0
        except (TypeError, ValueError):
            row[0, i] = 0.0
    prob = float(_model.predict_proba(row)[0][1])
    return round(prob * 100, 2)


def _rule_score(payload: dict, username: str, db):
    score = 0.0
    flags = []
    amount = float(payload.get("TransactionAmt") or payload.get("amount") or 0)

    from utils.security import make_device_hash
    device_hash = make_device_hash(payload)
    known = db.execute(
        "SELECT id FROM known_devices WHERE username=? AND device_hash=?",
        (username, device_hash)
    ).fetchone()
    if not known:
        score += RULE_NEW_DEVICE
        flags.append("New / unrecognised device detected")

    one_hour_ago = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    txn_1h = db.execute(
        "SELECT COUNT(*) FROM transactions WHERE username=? AND created_at >= ? AND status != 'blocked'",
        (username, one_hour_ago)
    ).fetchone()[0]
    if txn_1h >= 5:
        score += RULE_HIGH_VELOCITY
        flags.append(f"High velocity: {txn_1h} transactions in the last hour")

    five_min_ago = (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    txn_5m = db.execute(
        "SELECT COUNT(*) FROM transactions WHERE username=? AND created_at >= ?",
        (username, five_min_ago)
    ).fetchone()[0]
    if txn_5m >= 3:
        score += RULE_RAPID_FIRE
        flags.append(f"Rapid fire: {txn_5m} transactions in the last 5 minutes")

    thirty_days_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    avg_row = db.execute(
        "SELECT AVG(amount) FROM transactions WHERE username=? AND status='success' AND created_at >= ?",
        (username, thirty_days_ago)
    ).fetchone()
    avg_amount = float(avg_row[0] or 0)
    if avg_amount > 0 and amount > avg_amount * 5:
        score += RULE_UNUSUAL_AMOUNT
        flags.append(f"Unusual amount: Rs.{amount:,.0f} is {amount/avg_amount:.1f}x your 30-day average")

    if amount >= 50_000:
        score += RULE_LARGE_AMOUNT
        flags.append(f"Large transaction: Rs.{amount:,.0f} exceeds high-value threshold")

    current_hour = datetime.datetime.utcnow().hour
    if 0 <= current_hour < 4:
        score += RULE_LATE_NIGHT
        flags.append(f"Suspicious time: {current_hour:02d}:xx UTC (off-hours 00:00-04:00)")

    yesterday = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    failed = db.execute(
        "SELECT COUNT(*) FROM transactions WHERE username=? AND status IN ('failed','blocked') AND created_at >= ?",
        (username, yesterday)
    ).fetchone()[0]
    if failed >= 3:
        score += RULE_FAILED_RECENT
        flags.append(f"{failed} failed or blocked transactions in the last 24 hours")

    return min(score, 100.0), flags


def score_transaction(payload: dict, username: str, db) -> FraudResult:
    ml = _ml_score(payload)
    rule, flags = _rule_score(payload, username, db)

    # When ML unavailable or returns 0, rules carry full weight
    if ML_AVAILABLE and ml > 0:
        combined = ML_WEIGHT * ml + RULE_WEIGHT * rule
    else:
        combined = rule
        if combined < 10:
            combined = 10.0

    combined = round(min(combined, 100.0), 2)

    should_block = combined >= BLOCK_THRESHOLD
    require_otp  = not should_block and combined >= HIGH_THRESHOLD

    if combined >= HIGH_THRESHOLD:
        level = "HIGH"
        if should_block:
            flags.insert(0, f"Risk score {combined:.0f}/100 exceeds block threshold (>=75)")
    elif combined >= MEDIUM_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "LOW"

    log.info(
        "FraudScore[%s] ml=%.1f rule=%.1f combined=%.1f level=%s block=%s otp=%s",
        username, ml, rule, combined, level, should_block, require_otp
    )

    return FraudResult(
        risk_score   = combined,
        ml_score     = ml,
        rule_score   = rule,
        risk_level   = level,
        risk_flags   = flags,
        should_block = should_block,
        require_otp  = require_otp,
    )
