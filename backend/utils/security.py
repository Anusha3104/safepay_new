"""
security.py — Password hashing, rate limiting, input validation
===============================================================
All security primitives that are shared across routes live here.
"""

import os
import re
import time
import hashlib
import logging

log = logging.getLogger("safepay.security")

# ── Password hashing (PBKDF2-SHA256) ─────────────────────────────────────────
# 310,000 iterations is the OWASP recommended minimum for PBKDF2-SHA256 (2023).
# Each password gets a unique 32-byte random salt.

def hash_password(password: str) -> str:
    """Hash a plaintext password → 'hex_salt$hex_key'."""
    salt = os.urandom(32).hex()
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification."""
    try:
        salt, key_hex = stored.split("$", 1)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
        # hmac.compare_digest prevents timing attacks
        import hmac
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


# ── In-memory rate limiter ────────────────────────────────────────────────────
# Lightweight sliding-window rate limiter using a dict of timestamps.
# For production, replace with Redis (flask-limiter + Redis backend).

_rate_store: dict[str, list[float]] = {}


def rate_limit(key: str, max_calls: int, window_sec: int) -> bool:
    """
    Returns True (allowed) or False (limit exceeded).
    key: unique string, e.g. "login:127.0.0.1"
    """
    now   = time.time()
    calls = [t for t in _rate_store.get(key, []) if now - t < window_sec]
    if len(calls) >= max_calls:
        log.warning("Rate limit exceeded for key: %s (%d/%d in %ds)",
                    key, len(calls), max_calls, window_sec)
        return False
    calls.append(now)
    _rate_store[key] = calls
    return True


# ── Device fingerprinting ─────────────────────────────────────────────────────
def make_device_hash(data: dict) -> str:
    """
    Create a short device fingerprint from available signals.
    In production you'd hash many browser/hardware attributes.
    We combine: DeviceInfo, id_33 (screen), timezone, and user-agent.
    """
    raw = (
        f"{data.get('DeviceInfo', '')}"
        f"{data.get('id_33', '')}"
        f"{data.get('timezone', '')}"
        f"{data.get('user_agent', '')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Input validation helpers ──────────────────────────────────────────────────
_email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_registration(data: dict) -> str | None:
    """Return an error string or None if valid."""
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip()
    password = (data.get("password") or "").strip()

    if len(username) < 3:
        return "Username must be at least 3 characters"
    if len(username) > 30:
        return "Username must be at most 30 characters"
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Username may only contain letters, digits, and underscores"
    if not _email_re.match(email):
        return "Valid email is required"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if len(password) > 128:
        return "Password is too long"
    return None


def validate_transfer(data: dict) -> str | None:
    """Return an error string or None if the transfer payload is valid."""
    try:
        amount = float(data.get("amount") or data.get("TransactionAmt") or 0)
    except (TypeError, ValueError):
        return "Amount must be a number"
    if amount <= 0:
        return "Amount must be greater than zero"
    if amount > 100_000:
        return "Maximum transaction limit is ₹1,00,000"
    recipient = (data.get("recipient") or "").strip()
    if not recipient:
        return "Recipient is required"
    return None
