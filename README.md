# Nexus Control MVP (safe, consent-based)

This is a runnable full-stack starter for a multi-tenant device-management dashboard. It includes:
- Login with hashed passwords and signed JWT access tokens
- Super-admin customer creation and suspend/activate
- Tenant-isolated device inventory
- One-time device API keys and heartbeat endpoint
- Online/offline dashboard status, audit events
- Responsive purple web UI
- SQLite for local quick start; PostgreSQL via Docker Compose for deployment

It deliberately does **not** collect/forward SMS, OTP, banking messages, or calls. The Message Sync screen is a placeholder for a transparent, consent-based backup workflow. APK building and Telegram bot integration are not wired up in this MVP.

## Quick start (local development)

Requires Python 3.11+.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m app.create_admin
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 and sign in using the admin username/password you just created.

## Docker / PostgreSQL

```bash
cp .env.example .env
# Edit .env and replace every example secret with unique random values.
docker compose up --build -d
docker compose logs -f app
```

If `BOOTSTRAP_ADMIN_PASSWORD` is set to 12+ characters, the app creates the first super-admin on startup. Keep `.env` private. If the database already exists, changing bootstrap password will not reset an existing account.

Open `http://YOUR_SERVER_IP:8000` for initial testing only. For public deployment, put it behind HTTPS (Caddy/Nginx), restrict inbound ports, configure firewall, backups and monitoring, and do not expose PostgreSQL publicly.

## Device heartbeat API

A customer signs in, chooses **Devices → Register device**, and copies the device key shown once. A consented client integration sends:

```http
POST /api/device/heartbeat
Content-Type: application/json
X-Device-Key: <device-key>

{"device_name":"Field phone 01","device_model":"Pixel","platform":"Android"}
```

The key is stored hashed server-side. Rotate/revoke by removing the device and registering a replacement. Do not put device keys in source control or logs.

## API endpoints

- `POST /api/auth/token` — login (OAuth2 password form)
- `GET /api/me` — current account
- `GET /api/summary` — dashboard counters
- `GET/POST /api/customers` — super-admin only
- `PATCH /api/customers/{id}/status?active=true|false` — super-admin only
- `GET/POST/DELETE /api/devices` — tenant-scoped device inventory
- `POST /api/device/heartbeat` — device key auth
- `GET /api/audit` — scoped audit history
- `GET /api/health` — health check
- `POST /api/maintenance/mark-offline` — super-admin maintenance action

## Before production

This is an MVP, not a certified production system. Add rate limiting, CSRF strategy if cookie auth is introduced, refresh-token rotation, migrations (Alembic), structured logs, alerting, encrypted backups, key rotation, dependency scanning and load testing. Use an external worker/scheduler for offline status maintenance. For large scale, test realistic concurrent connections and heartbeat frequency before sizing infrastructure.
