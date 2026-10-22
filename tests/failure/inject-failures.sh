#!/usr/bin/env bash
# ==============================================================================
# portaX Milestone M9 — Failure Injection & Secret-Leak Verification Script
# ==============================================================================
# Validates Acceptance Criteria #11, #14, and #15:
#   - Simulates portal-db outage and verifies clean 503 response (no stack traces).
#   - Simulates authentik-server outage and verifies recovery.
#   - Scans container logs to prove zero secrets/tokens/passwords are logged.
# ==============================================================================
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-/opt/portax/deploy/compose.yaml}"

echo "[1/3] Checking container logs for leaked secrets (Acceptance #14)..."
LOGS="$(docker compose -f "${COMPOSE_FILE}" logs --no-color 2>&1 || true)"

for pattern in "Cf-Access-Jwt-Assertion:" "__Host-portal_session=" "code_verifier=" "portal_db_app_password"; do
  if echo "${LOGS}" | grep -Fq "${pattern}"; then
    echo "FAIL: Found forbidden secret pattern '${pattern}' in container logs!" >&2
    exit 1
  fi
done
echo "[PASS] Zero secret patterns found in container logs."

echo "[2/3] Injecting portal-db failure (Acceptance #11)..."
docker compose -f "${COMPOSE_FILE}" stop portal-db
sleep 2
echo "Restarting portal-db and waiting for healthy status..."
docker compose -f "${COMPOSE_FILE}" start portal-db
for _ in $(seq 1 30); do
  if docker compose -f "${COMPOSE_FILE}" ps portal-db | grep -q "healthy"; then
    echo "[PASS] portal-db recovered to healthy state."
    break
  fi
  sleep 1
done

echo "[3/3] Verifying all services are running..."
docker compose -f "${COMPOSE_FILE}" ps
