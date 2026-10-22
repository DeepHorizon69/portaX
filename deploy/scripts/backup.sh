#!/usr/bin/env bash
# ==============================================================================
# portaX Milestone M8 — Encrypted Off-Host Backup Script (pg_dump + restic)
# ==============================================================================
# Dumps both PostgreSQL databases (portal-db and authentik-db) consistently,
# archives configuration + encrypted dumps into an off-host restic repository,
# applies retention pruning, and pings Healthchecks (dead-man switch).
# ==============================================================================
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-/opt/portax/deploy/compose.yaml}"
STAGE_DIR="/var/backups/portax-stage"
export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-/etc/portax/secrets/restic_password}"
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY:-/var/backups/portax-restic-repo}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"

umask 0077
rm -rf "${STAGE_DIR}"
install -d -m 0700 -o root -g root "${STAGE_DIR}"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

echo "[1/4] Dumping portal-db (PostgreSQL custom format with checksums)..."
docker compose -f "${COMPOSE_FILE}" exec -T portal-db \
  pg_dump -U postgres -d portax --clean --if-exists --format=custom \
  > "${STAGE_DIR}/portal-db.dump"

echo "[2/4] Dumping authentik-db (PostgreSQL custom format)..."
docker compose -f "${COMPOSE_FILE}" exec -T authentik-db \
  pg_dump -U authentik -d authentik --clean --if-exists --format=custom \
  > "${STAGE_DIR}/authentik-db.dump"

sha256sum "${STAGE_DIR}/portal-db.dump" "${STAGE_DIR}/authentik-db.dump" > "${STAGE_DIR}/SHA256SUMS"

echo "[3/4] Backing up to encrypted restic repository (${RESTIC_REPOSITORY})..."
if ! restic snapshots >/dev/null 2>&1; then
  restic init
fi

restic backup \
  --tag "portax-scheduled" \
  "${STAGE_DIR}" \
  /opt/portax/deploy

echo "[4/4] Applying retention policy and checking repository integrity..."
restic forget --keep-hourly 24 --keep-daily 14 --keep-weekly 8 --keep-monthly 6 --prune
restic check --read-data-subset=10%

# Record backup freshness timestamp for the portal ops status view
date -u +"%Y-%m-%dT%H:%M:%SZ" > /var/backups/portax-last-success.txt

if [[ -n "${HEALTHCHECK_URL}" ]]; then
  curl -fsS -m 10 --retry 3 "${HEALTHCHECK_URL}" >/dev/null || true
fi

echo "[OK] Backup completed and verified."
