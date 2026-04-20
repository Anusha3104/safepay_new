"""
stats.py — Analytics & dashboard routes
=======================================
GET /stats          — user account statistics
GET /fraud-stats    — fraud overview for admin dashboard
GET /health         — health check
"""

import logging
import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.database import get_db
from fraud.fraud_engine import ML_AVAILABLE

log = logging.getLogger("safepay.stats")
stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/stats", methods=["GET"])
@jwt_required()
def stats():
    """
    Per-user statistics for the dashboard.
    Returns totals, blocked count, average risk, and balance.
    """
    username = get_jwt_identity()
    db       = get_db()

    # Aggregate over all this user's transactions
    row = db.execute(
        """SELECT
             COUNT(*)                                                 AS total_transactions,
             SUM(CASE WHEN status = 'blocked'    THEN 1 ELSE 0 END)  AS blocked_count,
             SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END)  AS suspicious_count,
             SUM(CASE WHEN status = 'success'    THEN 1 ELSE 0 END)  AS success_count,
             SUM(CASE WHEN status = 'success'    THEN amount ELSE 0 END) AS total_sent,
             AVG(risk_score)                                          AS avg_risk_score,
             MAX(risk_score)                                          AS max_risk_score
           FROM transactions
           WHERE username = ?""",
        (username,)
    ).fetchone()

    # Balance (always fresh from DB)
    user = db.execute(
        "SELECT balance FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Last 7 days trend — count transactions per day
    seven_days_ago = (
        datetime.datetime.utcnow() - datetime.timedelta(days=7)
    ).strftime("%Y-%m-%d")
    daily = db.execute(
        """SELECT DATE(created_at) AS day,
                  COUNT(*) AS count,
                  SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) AS blocked
           FROM transactions
           WHERE username = ? AND DATE(created_at) >= ?
           GROUP BY DATE(created_at)
           ORDER BY day""",
        (username, seven_days_ago)
    ).fetchall()

    return jsonify({
        "total_transactions":  row["total_transactions"]  or 0,
        "blocked_count":       row["blocked_count"]       or 0,
        "suspicious_count":    row["suspicious_count"]    or 0,
        "success_count":       row["success_count"]       or 0,
        "total_sent":          round(row["total_sent"]    or 0, 2),
        "avg_risk_score":      round(row["avg_risk_score"] or 0, 2),
        "max_risk_score":      round(row["max_risk_score"] or 0, 2),
        "balance":             round(user["balance"] if user else 0, 2),
        "daily_trend": [
            {"day": d["day"], "count": d["count"], "blocked": d["blocked"]}
            for d in daily
        ],
    }), 200


@stats_bp.route("/fraud-stats", methods=["GET"])
@jwt_required()
def fraud_stats():
    """
    Global fraud overview — used by the admin/security dashboard.
    Returns system-wide aggregates: total blocked, fraud rate,
    risk distribution, most risky users, and recent blocked transactions.
    """
    db = get_db()

    # Overall totals
    totals = db.execute(
        """SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN status='blocked'    THEN 1 ELSE 0 END) AS blocked,
             SUM(CASE WHEN status='suspicious' THEN 1 ELSE 0 END) AS suspicious,
             AVG(risk_score) AS avg_risk
           FROM transactions"""
    ).fetchone()

    total   = totals["total"] or 1   # avoid div-by-zero
    blocked = totals["blocked"] or 0

    # Risk level distribution
    dist = db.execute(
        """SELECT risk_level, COUNT(*) AS cnt
           FROM transactions
           GROUP BY risk_level"""
    ).fetchall()

    # Top 5 flagged users (most blocked transactions)
    flagged = db.execute(
        """SELECT username, COUNT(*) AS blocked_count
           FROM transactions
           WHERE status = 'blocked'
           GROUP BY username
           ORDER BY blocked_count DESC
           LIMIT 5"""
    ).fetchall()

    # Recent blocked transactions (last 10)
    recent_blocked = db.execute(
        """SELECT transaction_id, username, recipient, amount,
                  risk_score, risk_flags, created_at
           FROM transactions
           WHERE status = 'blocked'
           ORDER BY created_at DESC
           LIMIT 10"""
    ).fetchall()

    import json
    return jsonify({
        "total_transactions": totals["total"] or 0,
        "blocked_count":      blocked,
        "suspicious_count":   totals["suspicious"] or 0,
        "fraud_rate_pct":     round(blocked / total * 100, 2),
        "avg_risk_score":     round(totals["avg_risk"] or 0, 2),
        "risk_distribution": {
            d["risk_level"]: d["cnt"] for d in dist
        },
        "top_flagged_users": [
            {"username": u["username"], "blocked_count": u["blocked_count"]}
            for u in flagged
        ],
        "recent_blocked": [
            {
                "transaction_id": r["transaction_id"],
                "username":       r["username"],
                "recipient":      r["recipient"],
                "amount":         r["amount"],
                "risk_score":     r["risk_score"],
                "risk_flags":     json.loads(r["risk_flags"] or "[]"),
                "created_at":     r["created_at"],
            }
            for r in recent_blocked
        ],
        "ml_available": ML_AVAILABLE,
    }), 200


@stats_bp.route("/health", methods=["GET"])
def health():
    """Health check — does not require auth."""
    return jsonify({
        "status":       "ok",
        "ml_available": ML_AVAILABLE,
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
    }), 200
