"""
database.py — SQLite database initialisation & connection helper
================================================================
All schema definitions live here. We use SQLite with WAL mode for
concurrency and foreign key enforcement for data integrity.
"""

import os
import sqlite3
import logging
from flask import g

log = logging.getLogger("safepay.db")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "safepay.db")


# ── Connection helper ──────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    """
    Return a per-request SQLite connection stored in Flask's 'g' object.
    Using 'g' ensures each request gets exactly one connection that is
    automatically closed at request teardown.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row          # dict-like row access
        g.db.execute("PRAGMA journal_mode=WAL")  # allow concurrent reads
        g.db.execute("PRAGMA foreign_keys=ON")   # enforce FK constraints
    return g.db


def close_db(exc=None):
    """Teardown hook registered in app factory."""
    db = g.pop("db", None)
    if db:
        db.close()


# ── Schema ─────────────────────────────────────────────────────────────────────
def init_db():
    """
    Create all tables if they do not exist.
    Run once at application startup — safe to call repeatedly.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    -- ── Users ─────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    UNIQUE NOT NULL,
        email       TEXT    UNIQUE NOT NULL,
        password    TEXT    NOT NULL,           -- PBKDF2-SHA256 hash
        balance     REAL    DEFAULT 10000.0,    -- wallet balance in INR
        created_at  TEXT    DEFAULT (datetime('now')),
        last_login  TEXT
    );

    -- ── Transactions ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS transactions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id  TEXT    UNIQUE,         -- UUID for external reference
        username        TEXT    NOT NULL,
        recipient       TEXT,
        amount          REAL    NOT NULL,
        status          TEXT    NOT NULL,       -- 'success'|'blocked'|'suspicious'|'failed'
        payment_method  TEXT    DEFAULT 'wallet',
        risk_score      REAL    DEFAULT 0,
        risk_level      TEXT    DEFAULT 'LOW',  -- 'LOW'|'MEDIUM'|'HIGH'
        risk_flags      TEXT,                   -- JSON array of flag strings
        ml_score        REAL    DEFAULT 0,      -- raw ML probability (0-100)
        rule_score      REAL    DEFAULT 0,      -- rule-based score contribution
        device_hash     TEXT,                   -- SHA-256 device fingerprint (first 16 chars)
        device_info     TEXT,                   -- raw device info string
        location_lat    REAL,
        location_lon    REAL,
        ip_address      TEXT,
        razorpay_order_id   TEXT,               -- set when Razorpay flow is used
        razorpay_payment_id TEXT,
        created_at      TEXT    DEFAULT (datetime('now')),
        FOREIGN KEY (username) REFERENCES users(username)
    );

    -- ── Known devices per user ─────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS known_devices (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    NOT NULL,
        device_hash TEXT    NOT NULL,
        first_seen  TEXT    DEFAULT (datetime('now')),
        last_seen   TEXT    DEFAULT (datetime('now')),
        UNIQUE(username, device_hash)
    );

    -- ── Login audit log ───────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS login_attempts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT,
        ip_address  TEXT,
        success     INTEGER DEFAULT 0,
        created_at  TEXT    DEFAULT (datetime('now'))
    );

    -- ── Razorpay orders (for add-money flow) ──────────────────────────────
    CREATE TABLE IF NOT EXISTS razorpay_orders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id    TEXT    UNIQUE NOT NULL,     -- rzp_order_...
        username    TEXT    NOT NULL,
        amount      REAL    NOT NULL,            -- in INR
        amount_paise INTEGER NOT NULL,           -- in paise (×100)
        status      TEXT    DEFAULT 'created',  -- 'created'|'paid'|'failed'
        payment_id  TEXT,                        -- filled after verify
        created_at  TEXT    DEFAULT (datetime('now')),
        FOREIGN KEY (username) REFERENCES users(username)
    );

    -- ── Indices for common queries ─────────────────────────────────────────
    CREATE INDEX IF NOT EXISTS idx_txn_username  ON transactions(username);
    CREATE INDEX IF NOT EXISTS idx_txn_created   ON transactions(created_at);
    CREATE INDEX IF NOT EXISTS idx_txn_status    ON transactions(status);
    CREATE INDEX IF NOT EXISTS idx_devices_user  ON known_devices(username);
    """)
    conn.commit()
    conn.close()
    log.info("✅ Database initialised at %s", DB_PATH)
