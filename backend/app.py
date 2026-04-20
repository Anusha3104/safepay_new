"""
app.py — SafePay Flask Application Entry Point
===============================================
Application factory pattern keeps this file lean.
All logic lives in route blueprints and utility modules.

Run:
  cd safepay/backend
  pip install -r requirements.txt
  export JWT_SECRET_KEY="your-32-char-secret-here"
  python app.py
"""

import os
import sys
import logging
import datetime

from flask import Flask, jsonify, render_template   # ✅ ADDED render_template
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("safepay.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("safepay")


def create_app() -> Flask:
    """Application factory — creates and configures the Flask app."""
    app = Flask(__name__)

    # ── JWT configuration ─────────────────────────────────────────────────────
    app.config["JWT_SECRET_KEY"] = os.environ.get(
        "JWT_SECRET_KEY",
        "safepay-demo-secret-key-change-in-production-at-least-32chars"
    )
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=4)

    jwt = JWTManager(app)

    # ── JWT error handlers ────────────────────────────────────────────────────
    @jwt.unauthorized_loader
    def missing_token_cb(err):
        return jsonify({"msg": "Missing or invalid Authorization header"}), 401

    @jwt.invalid_token_loader
    def invalid_token_cb(err):
        return jsonify({"msg": "Invalid token"}), 401

    @jwt.expired_token_loader
    def expired_token_cb(jwt_header, jwt_payload):
        return jsonify({"msg": "Token has expired — please log in again"}), 401

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

    # ── Security headers ──────────────────────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        return response

    # ── Database ──────────────────────────────────────────────────────────────
    from models.database import init_db, close_db
    init_db()
    app.teardown_appcontext(close_db)

    # ── Register blueprints ───────────────────────────────────────────────────
    from routes.auth     import auth_bp
    from routes.payments import payments_bp
    from routes.stats    import stats_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(payments_bp)
    app.register_blueprint(stats_bp)

    # ✅ ADDED: Serve frontend
    @app.route("/")
    def home():
        return render_template("index.html")

    log.info("✅ SafePay app created — routes registered")
    return app


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()

    # ✅ ADDED: Cloud-compatible port
    port = int(os.environ.get("PORT", 5000))

    log.info(f"🚀 SafePay backend starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)