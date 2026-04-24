#!/bin/sh
# HoneyDash pgAdmin pre-initialisation script
# Runs BEFORE the stock /entrypoint.sh to:
#   1. Create a libpq .pgpass file (libpq fallback)
#   2. Import servers from servers.json into pgadmin4.db
#   3. Pre-seed the server password so pgAdmin never shows a password dialog
#   4. Hand control back to the standard pgAdmin entrypoint

set -e

# ── 1. pgpass (libpq fallback) ───────────────────────────────────────────────
printf '*:5432:*:honeydash:honeydash_pass\n' > /tmp/pgpass
chmod 600 /tmp/pgpass
echo "[pgadmin-init] Created /tmp/pgpass"

# ── 2. Initialise DB + admin user (idempotent) ────────────────────────────────
cd /pgadmin4
python3 setup.py \
    --email    "${PGADMIN_DEFAULT_EMAIL:-admin@honeydash.com}" \
    --password "${PGADMIN_DEFAULT_PASSWORD:-admin}" \
    2>/dev/null || true
echo "[pgadmin-init] DB setup done"

# ── 3. Import servers from JSON (idempotent – existing servers are updated,  ──
#       but the Password column is intentionally NOT touched by pgAdmin's own  ──
#       load_database_servers(), so our seed in step 4 survives a re-import)  ──
if [ -n "${PGADMIN_SERVER_JSON_FILE}" ]; then
    python3 setup.py \
        --load-servers "${PGADMIN_SERVER_JSON_FILE}" \
        --user "${PGADMIN_DEFAULT_EMAIL:-admin@honeydash.com}" \
        2>/dev/null || true
    echo "[pgadmin-init] Servers imported from ${PGADMIN_SERVER_JSON_FILE}"
fi

# ── 4. Pre-seed the encrypted server password ────────────────────────────────
# Uses the same key-derivation as pgAdmin's own crypto.py:
#   fernet_key = base64url( SHA256( ENCRYPTION_KEY ) )
python3 - <<'PYEOF'
import os, sys, sqlite3, hashlib, base64

DB   = '/var/lib/pgadmin/pgadmin4.db'
KEY  = os.environ.get('PGADMIN_CONFIG_ENCRYPTION_KEY', '')
PASS = b'honeydash_pass'
NAME = 'HoneyDash PostgreSQL'

if not os.path.exists(DB):
    print('[pgadmin-init] DB not found – will seed on next start')
    sys.exit(0)

if not KEY:
    print('[pgadmin-init] PGADMIN_CONFIG_ENCRYPTION_KEY not set – skipping seed')
    sys.exit(0)

try:
    from cryptography.fernet import Fernet

    fernet_key    = base64.urlsafe_b64encode(hashlib.sha256(KEY.encode()).digest())
    encrypted_pass = Fernet(fernet_key).encrypt(PASS).decode()

    conn = sqlite3.connect(DB)
    n = conn.execute(
        'UPDATE server SET password=? WHERE name=?',
        (encrypted_pass, NAME)
    ).rowcount
    conn.commit()
    conn.close()

    if n:
        print(f'[pgadmin-init] Pre-seeded password for {n} server(s) – pgAdmin will auto-connect')
    else:
        print(f'[pgadmin-init] Server "{NAME}" not in DB yet (will be seeded on next restart)')

except ImportError:
    print('[pgadmin-init] cryptography not available – skipping password seed')
except Exception as exc:
    print(f'[pgadmin-init] Seed error: {exc}')
PYEOF

# ── 5. Hand off to the standard pgAdmin entrypoint ───────────────────────────
exec /entrypoint.sh
