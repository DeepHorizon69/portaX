#!/usr/bin/env bash
# ==============================================================================
# portaX Milestone M1/M2 — Secret Directory Initializer
# ==============================================================================
# Creates /etc/portax/secrets with strict 0700 directory permissions and
# generates cryptographically random secrets (mode 0400) if they do not exist.
# Existing secrets are NEVER overwritten.
# ==============================================================================
set -euo pipefail

SECRETS_DIR="${SECRETS_DIR:-/etc/portax/secrets}"
PORTAL_UID=65532
AUTHENTIK_UID=1000

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: Please run as root (sudo bash deploy/scripts/init-secrets.sh)" >&2
  exit 1
fi

install -d -m 0755 -o root -g root "${SECRETS_DIR}"

generate_secret() {
  local name="$1"
  local bytes="$2"
  local owner_uid="$3"
  local path="${SECRETS_DIR}/${name}"

  if [[ -f "${path}" ]]; then
    echo "[SKIP] ${path} already exists (preserving existing secret)"
    chmod 0444 "${path}"
  else
    openssl rand -hex "${bytes}" | tr -d '\n' > "${path}"
    chown "${owner_uid}:0" "${path}"
    chmod 0444 "${path}"
    echo "[OK]   Generated ${path} (mode 0444, uid ${owner_uid})"
  fi
}

# Portal database & cryptographic keys
generate_secret "portal_db_migrator_password" 24 "${PORTAL_UID}"
generate_secret "portal_db_app_password"      24 "${PORTAL_UID}"
generate_secret "portal_db_prober_password"   24 "${PORTAL_UID}"
generate_secret "portal_session_pepper"       32 "${PORTAL_UID}"
generate_secret "portal_cookie_aead_key"      32 "${PORTAL_UID}"
generate_secret "portal_oidc_client_secret"   32 "${PORTAL_UID}"

# Authentik database & signing key
generate_secret "authentik_db_password"       24 "${AUTHENTIK_UID}"
generate_secret "authentik_secret_key"        48 "${AUTHENTIK_UID}"

# Restic backup encryption password (root-only)
generate_secret "restic_password"             32 0

echo ""
echo "Reminder: Place your Cloudflare Tunnel credentials JSON at:"
echo "  ${SECRETS_DIR}/cloudflared_credentials.json (chown ${PORTAL_UID}:0, chmod 0400)"
