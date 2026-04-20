# SafePay — AI-Powered Fraud Detection Payment System

A production-grade fintech application with a **3-layer hybrid fraud detection engine**,
JWT authentication, Razorpay integration, and a full single-page frontend.

---

## Architecture

```
safepay/
├── backend/
│   ├── app.py                ← Flask application factory
│   ├── fraud_model.pkl       ← LightGBM model (IEEE-CIS, 590K txns, 432 features)
│   ├── feature_schema.pkl    ← Feature names list
│   ├── retrain_model.py      ← Model retraining pipeline
│   ├── requirements.txt
│   ├── fraud/
│   │   └── fraud_engine.py   ← Hybrid ML + rules scoring
│   ├── models/
│   │   └── database.py       ← Schema, init_db(), get_db()
│   ├── routes/
│   │   ├── auth.py           ← /register /login /me /balance
│   │   ├── payments.py       ← /create-order /verify-payment /transfer /fraud-check
│   │   └── stats.py          ← /stats /fraud-stats /health
│   └── utils/
│       └── security.py       ← PBKDF2 hashing, rate limiter, device fingerprint
└── frontend/
    └── index.html            ← Complete SPA (no build step required)
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### 1. Backend

```bash
cd safepay/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set a secure JWT secret (required)
export JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# Optional: Razorpay test keys (get from dashboard.razorpay.com)
export RAZORPAY_KEY_ID="rzp_test_your_key_here"
export RAZORPAY_KEY_SECRET="your_secret_here"

# Run
python app.py
# Server starts at http://127.0.0.1:5000
```

### 2. Frontend

```bash
cd safepay/frontend
python3 -m http.server 8080
# Open http://localhost:8080
```

Or just open `frontend/index.html` directly in your browser.

---

## API Reference

| Method | Endpoint         | Auth | Description                        |
|--------|-----------------|------|------------------------------------|
| GET    | `/health`        | —    | Health check + ML status           |
| POST   | `/register`      | —    | Create account                     |
| POST   | `/login`         | —    | Get JWT token                      |
| GET    | `/me`            | JWT  | Current user profile               |
| GET    | `/balance`       | JWT  | Current wallet balance             |
| POST   | `/create-order`  | JWT  | Create Razorpay order              |
| POST   | `/verify-payment`| JWT  | Verify signature + credit wallet   |
| POST   | `/transfer`      | JWT  | P2P wallet transfer (fraud-checked)|
| POST   | `/fraud-check`   | JWT  | Dry-run fraud score (no commit)    |
| GET    | `/transactions`  | JWT  | Transaction history                |
| GET    | `/stats`         | JWT  | Personal account statistics        |
| GET    | `/fraud-stats`   | JWT  | System-wide fraud analytics        |

### Example: Transfer

```bash
curl -X POST http://localhost:5000/transfer \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1500,
    "recipient": "alice",
    "TransactionDT": 86400,
    "timezone": "Asia/Kolkata",
    "DeviceInfo": "Chrome 121",
    "id_33": "1920x1080",
    "lat": 26.9124,
    "lon": 75.7873
  }'
```

---

## Fraud Detection — How It Works

### Layer 1 — LightGBM ML Model
- **Dataset**: IEEE-CIS Fraud Detection (590,540 real transactions)
- **Features**: 432 — transaction amount, timing deltas, card/email hashes,
  device identity (id_01–id_38), behavioural aggregates (C1–C14, D1–D15),
  Vesta engineered features (V1–V339)
- **Output**: probability 0→1, scaled to 0→100

### Layer 2 — Behavioural Rule Engine

| Rule | Score Boost | Trigger Condition |
|------|:-----------:|-------------------|
| New device | **+25** | Device fingerprint never seen for this user |
| High velocity | **+20** | ≥5 transactions in last 60 minutes |
| Rapid fire | **+15** | ≥3 transactions in last 5 minutes |
| Unusual amount | **+20** | >5× the user's 30-day average |
| Large amount | **+15** | ≥₹50,000 absolute |
| Late night | **+10** | 00:00–04:00 UTC |
| Multiple failures | **+10** | ≥3 blocked/failed in last 24 hours |

### Layer 3 — Combined Scoring & Action

```
final_score = (ML_score × 0.70) + (rule_score × 0.30)
```

| Score | Level | Action |
|-------|-------|--------|
| < 30 | 🟢 LOW | ✅ Approve normally |
| 30–64 | 🟡 MEDIUM | ⚠️ Approve + log as 'suspicious' |
| 65–74 | 🔴 HIGH | 🔶 Approve + flag for review |
| ≥ 75 | 🔴 HIGH | 🚫 **Block** transaction |

---

## Security

| Feature | Implementation |
|---------|----------------|
| Password storage | PBKDF2-SHA256, 310,000 iterations, 32-byte random salt |
| JWT sessions | HS256, 4-hour expiry, loaded from env var |
| Rate limiting | Login: 10/15min per IP; Register: 5/hr per IP; Transfer: 15/hr per user |
| SQL injection | Parameterised queries throughout — no string interpolation |
| Balance safety | Checked before deduction; DB-level atomicity |
| Device tracking | SHA-256 fingerprint (device+screen+timezone+UA) |
| Audit logging | Every login attempt recorded in `login_attempts` table |
| Security headers | X-Content-Type-Options, X-Frame-Options, Referrer-Policy |

---

## Razorpay Integration

```
User → /create-order {amount}
     ← {order_id, key_id, amount, currency}

User opens Razorpay modal with order_id
User pays → Razorpay success handler fires

User → /verify-payment {razorpay_order_id, razorpay_payment_id, razorpay_signature}
     ← {status: "success", new_balance}
```

HMAC-SHA256 signature verification:
```python
expected = hmac.new(
    RAZORPAY_KEY_SECRET.encode(),
    f"{order_id}|{payment_id}".encode(),
    hashlib.sha256
).hexdigest()
assert hmac.compare_digest(expected, received_signature)
```

**Test card**: 4111 1111 1111 1111, CVV: 123, any future expiry.

---

## Model Retraining

```bash
cd safepay/backend
source venv/bin/activate
python retrain_model.py
```

The script:
1. Loads all labeled transactions from `safepay.db`
2. Engineers 10 features (amount, z-score, velocity, device change, etc.)
3. Augments with synthetic fraud/legit samples if data is sparse
4. Trains XGBoost (or RandomForest fallback)
5. Prints precision/recall/AUC on a held-out test set
6. Archives the old model with a timestamp
7. Atomically replaces `fraud_model.pkl` and `feature_schema.pkl`

**Scheduled retraining (crontab)**:
```cron
0 3 * * * cd /path/to/safepay/backend && source venv/bin/activate && python retrain_model.py >> retrain.log 2>&1
```

---

## Database Schema

```sql
users          (id, username, email, password, balance, created_at, last_login)
transactions   (id, transaction_id, username, recipient, amount, status,
                payment_method, risk_score, risk_level, risk_flags,
                ml_score, rule_score, device_hash, device_info,
                location_lat, location_lon, ip_address,
                razorpay_order_id, razorpay_payment_id, created_at)
known_devices  (id, username, device_hash, first_seen, last_seen)
login_attempts (id, username, ip_address, success, created_at)
razorpay_orders(id, order_id, username, amount, amount_paise,
                status, payment_id, created_at)
```

---

## Before Going to Production

1. **Change JWT secret**: `export JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"` — never commit it
2. **Use PostgreSQL**: Replace SQLite with `psycopg2` + connection pooling
3. **Lock down CORS**: Change `"*"` to your frontend domain
4. **HTTPS**: Required for geolocation API — use nginx/Caddy
5. **Real Razorpay keys**: From [dashboard.razorpay.com](https://dashboard.razorpay.com)
6. **Rate limiting with Redis**: Replace the in-memory limiter with `flask-limiter` + Redis
7. **Switch to bcrypt**: `pip install bcrypt` for stronger password hashing
8. **Add email verification**: For new account registrations
