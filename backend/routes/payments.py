"""
payments.py — Wallet & Razorpay payment routes
"""

import os
import uuid
import json
import hmac
import hashlib
import logging

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.database import get_db
from utils.security  import (
    rate_limit, make_device_hash, validate_transfer
)
from fraud.fraud_engine import score_transaction

log = logging.getLogger("safepay.payments")
payments_bp = Blueprint("payments", __name__)

RAZORPAY_KEY_ID     = os.environ.get("RAZORPAY_KEY_ID",     "rzp_test_placeholder")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "razorpay_secret_placeholder")


@payments_bp.route("/create-order", methods=["POST"])
@jwt_required()
def create_order():
    username = get_jwt_identity()
    data     = request.get_json(silent=True) or {}
    try:
        amount = float(data.get("amount") or 0)
        if amount < 100 or amount > 100_000:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"msg": "Amount must be between Rs.100 and Rs.1,00,000"}), 400

    amount_paise = int(amount * 100)

    try:
        import razorpay
        client   = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        order    = client.order.create({"amount": amount_paise, "currency": "INR", "payment_capture": 1,
                                        "notes": {"username": username, "purpose": "wallet_topup"}})
        order_id = order["id"]
        log.info("Razorpay order created: %s for %s Rs.%.2f", order_id, username, amount)
    except Exception as exc:
        order_id = f"order_DEMO_{uuid.uuid4().hex[:12].upper()}"
        log.warning("Razorpay unavailable (%s). Demo order: %s", exc, order_id)

    db = get_db()
    db.execute(
        "INSERT INTO razorpay_orders (order_id, username, amount, amount_paise) VALUES (?, ?, ?, ?)",
        (order_id, username, amount, amount_paise)
    )
    db.commit()

    return jsonify({"order_id": order_id, "amount": amount, "currency": "INR", "key_id": RAZORPAY_KEY_ID}), 200


@payments_bp.route("/verify-payment", methods=["POST"])
@jwt_required()
def verify_payment():
    username = get_jwt_identity()
    data     = request.get_json(silent=True) or {}
    order_id   = data.get("razorpay_order_id",   "")
    payment_id = data.get("razorpay_payment_id", "")
    signature  = data.get("razorpay_signature",  "")

    if not all([order_id, payment_id, signature]):
        return jsonify({"msg": "Missing payment verification fields"}), 400

    db    = get_db()
    order = db.execute(
        "SELECT * FROM razorpay_orders WHERE order_id = ? AND username = ?",
        (order_id, username)
    ).fetchone()

    if not order:
        return jsonify({"msg": "Order not found or does not belong to this user"}), 404
    if order["status"] == "paid":
        return jsonify({"msg": "Order has already been processed"}), 409

    # Validate amount is positive
    amount = float(order["amount"])
    if amount <= 0 or amount > 100_000:
        return jsonify({"msg": "Invalid order amount"}), 400

    # Signature verification (skip for demo orders)
    if not order_id.startswith("order_DEMO_"):
        expected = hmac.new(
            RAZORPAY_KEY_SECRET.encode(),
            f"{order_id}|{payment_id}".encode(),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            log.warning("Signature mismatch for order %s (user %s)", order_id, username)
            db.execute("UPDATE razorpay_orders SET status='failed' WHERE order_id=?", (order_id,))
            db.commit()
            return jsonify({"msg": "Payment signature verification failed"}), 400

    db.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
    db.execute("UPDATE razorpay_orders SET status='paid', payment_id=? WHERE order_id=?", (payment_id, order_id))

    txn_id = str(uuid.uuid4())
    db.execute(
        """INSERT INTO transactions
           (transaction_id, username, recipient, amount, status,
            payment_method, risk_score, risk_level, risk_flags,
            razorpay_order_id, razorpay_payment_id)
           VALUES (?, ?, ?, ?, 'success', 'razorpay', 0, 'LOW', '[]', ?, ?)""",
        (txn_id, username, "WALLET_CREDIT", amount, order_id, payment_id)
    )
    db.commit()

    new_balance = db.execute("SELECT balance FROM users WHERE username = ?", (username,)).fetchone()["balance"]
    log.info("Payment verified: %s +Rs.%.2f -> balance=Rs.%.2f", username, amount, new_balance)
    return jsonify({"status": "success", "msg": f"Rs.{amount:,.2f} added to wallet", "new_balance": round(new_balance, 2)}), 200


@payments_bp.route("/transfer", methods=["POST"])
@jwt_required()
def transfer():
    username = get_jwt_identity()
    ip       = request.remote_addr

    if not rate_limit(f"send:{username}", 15, 3600):
        return jsonify({"msg": "Too many transactions. Slow down."}), 429

    payload   = request.get_json(silent=True) or {}
    err       = validate_transfer(payload)
    if err:
        return jsonify({"msg": err}), 400

    amount    = float(payload.get("amount") or payload.get("TransactionAmt") or 0)
    recipient = payload.get("recipient", "").strip()

    if recipient.lower() == username.lower():
        return jsonify({"msg": "You cannot transfer money to yourself"}), 400

    db   = get_db()
    user = db.execute("SELECT balance FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    balance = float(user["balance"])
    if amount > balance:
        return jsonify({"msg": f"Insufficient balance. Available: Rs.{balance:,.2f}"}), 400

    payload["TransactionAmt"] = amount

    # Run fraud engine
    result      = score_transaction(payload, username, db)
    device_hash = make_device_hash(payload)
    txn_id      = str(uuid.uuid4())

    # Upsert device record
    existing = db.execute(
        "SELECT id FROM known_devices WHERE username=? AND device_hash=?",
        (username, device_hash)
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE known_devices SET last_seen = datetime('now') WHERE username=? AND device_hash=?",
            (username, device_hash)
        )
    else:
        db.execute("INSERT INTO known_devices (username, device_hash) VALUES (?, ?)", (username, device_hash))

    # Determine transaction status
    if result.should_block:
        status = "blocked"
    elif result.risk_level in ("MEDIUM", "HIGH"):
        status = "suspicious"
    else:
        status = "success"

    # Always record the attempt
    db.execute(
        """INSERT INTO transactions
           (transaction_id, username, recipient, amount, status,
            payment_method, risk_score, risk_level, risk_flags,
            ml_score, rule_score, device_hash, device_info,
            location_lat, location_lon, ip_address)
           VALUES (?, ?, ?, ?, ?, 'wallet', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            txn_id, username, recipient, amount, status,
            result.risk_score, result.risk_level, json.dumps(result.risk_flags),
            result.ml_score, result.rule_score, device_hash,
            payload.get("DeviceInfo", ""),
            payload.get("lat"), payload.get("lon"), ip,
        )
    )

    if result.should_block:
        db.commit()
        log.warning("Transfer BLOCKED: %s -> %s Rs.%.2f (score=%.1f)", username, recipient, amount, result.risk_score)
        return jsonify({
            "status":         "blocked",
            "msg":            "Transaction blocked by fraud detection system",
            "risk_score":     result.risk_score,
            "risk_level":     result.risk_level,
            "risk_flags":     result.risk_flags,
            "transaction_id": txn_id,
        }), 403

    # Process transfer
    new_sender_balance = round(balance - amount, 2)
    db.execute("UPDATE users SET balance = ? WHERE username = ?", (new_sender_balance, username))

    recipient_user = db.execute("SELECT username FROM users WHERE username = ?", (recipient,)).fetchone()
    if recipient_user:
        db.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, recipient))

    db.commit()
    log.info("Transfer %s: %s -> %s Rs.%.2f (score=%.1f)", status.upper(), username, recipient, amount, result.risk_score)

    response = {
        "status":            status,
        "msg":               f"Rs.{amount:,.2f} sent to {recipient}",
        "remaining_balance": new_sender_balance,
        "risk_score":        result.risk_score,
        "risk_level":        result.risk_level,
        "risk_flags":        result.risk_flags,
        "require_otp":       result.require_otp,
        "transaction_id":    txn_id,
    }
    if status == "suspicious":
        response["warning"] = "Transaction allowed but flagged for review"

    return jsonify(response), 200


@payments_bp.route("/transactions", methods=["GET"])
@jwt_required()
def transactions():
    username = get_jwt_identity()
    limit    = min(int(request.args.get("limit", 20)), 100)
    offset   = max(int(request.args.get("offset", 0)), 0)
    status   = request.args.get("status", "")

    db     = get_db()
    params = [username]
    where  = "WHERE username = ?"

    if status:
        where   += " AND status = ?"
        params.append(status)

    rows = db.execute(
        f"""SELECT transaction_id, username, recipient, amount, status,
                   risk_score, risk_level, risk_flags, ml_score, rule_score,
                   payment_method, created_at
            FROM transactions {where}
            ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        params + [limit, offset]
    ).fetchall()

    result = []
    for r in rows:
        try:
            flags = json.loads(r["risk_flags"] or "[]")
        except Exception:
            flags = []
        result.append({
            "transaction_id": r["transaction_id"],
            "recipient":      r["recipient"],
            "amount":         r["amount"],
            "status":         r["status"],
            "risk_score":     r["risk_score"],
            "risk_level":     r["risk_level"],
            "risk_flags":     flags,
            "ml_score":       r["ml_score"],
            "rule_score":     r["rule_score"],
            "payment_method": r["payment_method"],
            "created_at":     r["created_at"],
        })

    return jsonify(result), 200


@payments_bp.route("/fraud-check", methods=["POST"])
@jwt_required()
def fraud_check():
    username = get_jwt_identity()
    payload  = request.get_json(silent=True) or {}

    try:
        amount = float(payload.get("amount") or payload.get("TransactionAmt") or 0)
        if amount <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"msg": "Valid amount required"}), 400

    payload["TransactionAmt"] = amount
    db     = get_db()
    result = score_transaction(payload, username, db)

    return jsonify({
        "risk_score":  result.risk_score,
        "risk_level":  result.risk_level,
        "risk_flags":  result.risk_flags,
        "ml_score":    result.ml_score,
        "rule_score":  result.rule_score,
        "would_block": result.should_block,
        "require_otp": result.require_otp,
        "recommendation": (
            "BLOCK" if result.should_block
            else "OTP"  if result.require_otp
            else "WARN" if result.risk_level == "MEDIUM"
            else "ALLOW"
        ),
    }), 200
