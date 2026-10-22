#!/usr/bin/env bash
# ==============================================================================
# portaX Host Ops Status Collector (No Docker Socket Required)
# ==============================================================================
# Runs on host cron every 5 minutes and writes sanitized, non-sensitive operational
# status metrics into the read-only volume mounted by the portal container.
# Never includes IPs, hostnames, secrets, or container env vars.
# ==============================================================================
set -euo pipefail

OUT_FILE="${OUT_FILE:-/var/lib/docker/volumes/portax_vol_ops_status/_data/status.json}"
LAST_BACKUP_FILE="/var/backups/portax-last-success.txt"

DISK_USED_PCT="$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')"
MEM_AVAILABLE_MB="$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)"
LOAD_1M="$(awk '{print $1}' /proc/loadavg)"
LAST_BACKUP="never"
if [[ -f "${LAST_BACKUP_FILE}" ]]; then
  LAST_BACKUP="$(cat "${LAST_BACKUP_FILE}" | tr -d '\n')"
fi

TMP_FILE="${OUT_FILE}.tmp"
cat > "${TMP_FILE}" <<EOF
{
  "collected_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "disk_used_percent": ${DISK_USED_PCT},
  "mem_available_mb": ${MEM_AVAILABLE_MB},
  "load_1m": "${LOAD_1M}",
  "last_backup_utc": "${LAST_BACKUP}"
}
EOF
chmod 0644 "${TMP_FILE}"
mv "${TMP_FILE}" "${OUT_FILE}"
