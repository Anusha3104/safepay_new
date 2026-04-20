"""
auth.py — Authentication routes
================================
POST /register   — create new account
POST /login      — obtain JWT
GET  /me         — current user profile
GET  /balance    — current wallet balance
"""

import logging
import sqlite3

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity
)

from models.database import get_db
from utils.security  import (
    hash_password, verify_password,
    rate_limit, validate_registration
)

log = logging.getLogger("safepay.auth")
auth_bp = Blueprint("auth", __name__)


# ── /register ──────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Create a new user account.
    Rate limited: 5 attempts per IP per hour to prevent account spam.
    Passwords are hashed with PBKDF2-SHA256 before storage.
    """
    ip = request.remote_addr
    if not rate_limit(f"reg:{ip}", 5, 3600):
        return jsonify({"msg": "Too many registration attempts. Try again later."}), 429

    data = request.get_json(silent=True) or {}

    # Validate all fields at once
    err = validate_registration(data)
    if err:
        return jsonify({"msg": err}), 400

    username = data["username"].strip().lower()
    email    = data["email"].strip().lower()
    password = data["password"].strip()

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hash_password(password))
        )
        db.commit()
        log.info("New user registered: %s from %s", username, ip)
        return jsonify({"msg": "Account created successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"msg": "Username or email already exists"}), 409


# ── /login ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and return a JWT access token.
    Rate limited: 10 attempts per IP per 15 minutes.
    Every attempt (success or failure) is logged for audit.
    """
    ip = request.remote_addr
    if not rate_limit(f"login:{ip}", 10, 900):
        return jsonify({"msg": "Too many login attempts. Try again in 15 minutes."}), 429

    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    ok   = bool(user and verify_password(password, user["password"]))

    # Always log the attempt (for security auditing)
    db.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip, 1 if ok else 0)
    )

    if ok:
        db.execute(
            "UPDATE users SET last_login = datetime('now') WHERE username = ?",
            (username,)
        )
        db.commit()
        log.info("Login SUCCESS: %s from %s", username, ip)
        return jsonify({
            "access_token": create_access_token(identity=username),
            "username":     username,
            "balance":      user["balance"],
            "email":        user["email"],
        }), 200

    db.commit()
    log.warning("Login FAILED: %s from %s", username, ip)
    return jsonify({"msg": "Invalid username or password"}), 401


# ── /me ────────────────────────────────────────────────────────────────────────
@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """Return the current user's profile (requires valid JWT)."""
    username = get_jwt_identity()
    db       = get_db()
    user     = db.execute(
        "SELECT username, email, balance, created_at, last_login FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "username":   user["username"],
        "email":      user["email"],
        "balance":    round(user["balance"], 2),
        "created_at": user["created_at"],
        "last_login": user["last_login"],
    }), 200


# ── /balance ───────────────────────────────────────────────────────────────────
@auth_bp.route("/balance", methods=["GET"])
@jwt_required()
def balance():
    """Return the current wallet balance.  Always reads live from DB."""
    username = get_jwt_identity()
    db       = get_db()
    row      = db.execute(
        "SELECT balance FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not row:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({"balance": round(row["balance"], 2)}), 200
