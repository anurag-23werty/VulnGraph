#!/usr/bin/env bash
set -e

echo "=================================================="
echo " Starting VulnGraph Cloud Container Runtime"
echo "=================================================="

# Determine if we should start local embedded FalkorDB
# If FALKORDB_HOST is unset, empty, localhost, or 127.0.0.1:
TARGET_HOST="${FALKORDB_HOST:-localhost}"

if [ "$TARGET_HOST" = "localhost" ] || [ "$TARGET_HOST" = "127.0.0.1" ] || [ "$TARGET_HOST" = "0.0.0.0" ]; then
    echo "[FalkorDB] Launching embedded FalkorDB engine on 127.0.0.1:6379..."
    mkdir -p /var/lib/falkordb/data
    redis-server --loadmodule /var/lib/falkordb/bin/falkordb.so --dir /var/lib/falkordb/data --daemonize yes

    # Wait for engine readiness
    echo "[FalkorDB] Verifying engine readiness..."
    READY=0
    for i in $(seq 1 30); do
        if redis-cli ping > /dev/null 2>&1; then
            READY=1
            echo "[FalkorDB] Engine ready (PONG received)."
            break
        fi
        sleep 0.5
    done

    if [ "$READY" -eq 0 ]; then
        echo "[ERROR] Failed to start embedded FalkorDB within 15 seconds."
        exit 1
    fi

    # Initialize graph schema & seed vulnerability topology if not yet initialized
    echo "[VulnGraph] Applying database schema migrations..."
    python backend/migrate.py || true

    echo "[VulnGraph] Seeding OSV and benchmark scenario graph data..."
    python backend/ingest.py || true
else
    echo "[VulnGraph] Connecting to remote FalkorDB at ${TARGET_HOST}:${FALKORDB_PORT:-6379}..."
fi

# Launch Web Application on assigned port (Render assigns $PORT)
APP_PORT="${PORT:-${API_PORT:-8000}}"
echo "[VulnGraph] Starting Web Application on port ${APP_PORT}..."
export API_PORT="${APP_PORT}"
exec python backend/main.py
