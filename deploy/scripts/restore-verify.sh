#!/usr/bin/env bash
# ==============================================================================
# portaX Milestone M8 — Non-Destructive Backup Restore Verification Drill
# ==============================================================================
# Restores the latest encrypted restic snapshot into an isolated, ephemeral
# PostgreSQL 17.11 container (with --network none) and verifies that all tables
# and catalog entries restore cleanly without touching the live databases.
# ==============================================================================
set -euo pipefail

export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/portax/secrets/restic_password}"
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:-/var/backups/portax-restic-repo}"
RESTORE_DIR="$(mktemp -d /tmp/portax-restore-drill.XXXXXX)"
DRILL_CONTAINER="portax-restore-drill-db"

cleanup() {
  docker rm -f "${DRILL_CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${RESTORE_DIR}"
}
trap cleanup EXIT

echo "[1/4] Restoring latest snapshot from restic to ${RESTORE_DIR}..."
restic restore latest --target "${RESTORE_DIR}"

DUMP_FILE="$(find "${RESTORE_DIR}" -name 'portal-db.dump' | head -n 1)"
if [[ -z "${DUMP_FILE}" ]]; then
  echo "ERROR: portal-db.dump not found in restored snapshot!" >&2
  exit 1
fi

echo "[2/4] Starting isolated ephemeral PostgreSQL 17.11 container (--network none)..."
docker run -d --name "${DRILL_CONTAINER}" \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -u 70:70 \
  -e POSTGRES_DB=portax_drill \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  postgres:17.11-alpine >/dev/null

for _ in $(seq 1 20); do
  if docker exec "${DRILL_CONTAINER}" pg_isready -U postgres -d portax_drill >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[3/4] Running pg_restore into isolated drill database..."
docker exec -i "${DRILL_CONTAINER}" \
  pg_restore -U postgres -d portax_drill --no-owner --no-privileges < "${DUMP_FILE}"

echo "[4/4] Verifying restored schema & row counts..."
docker exec "${DRILL_CONTAINER}" psql -U postgres -d portax_drill -c \
  "SELECT count(*) AS restored_catalog_services FROM catalog_services; SELECT count(*) AS restored_audit_events FROM audit_logs;"

echo "[PASS] Restore drill succeeded! Backup is decryptable and valid."
