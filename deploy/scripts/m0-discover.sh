#!/usr/bin/env bash
# ==============================================================================
# portaX Milestone M0 — Read-Only Host, Runtime & Network Discovery Script
# ==============================================================================
# SAFETY: This script executes ONLY read-only diagnostic commands.
# It does NOT modify files, containers, networks, firewall rules, or packages.
# ==============================================================================
set -euo pipefail

echo "=================================================================="
echo " portaX M0 Read-Only Discovery — $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "=================================================================="

echo -e "\n[1/8] OS & Kernel Version:"
uname -a
cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID)=' || true

echo -e "\n[2/8] CPU, Memory & Swap Headroom:"
nproc --all
free -h

echo -e "\n[3/8] Disk Space & Inode Usage:"
df -hT -x tmpfs -x devtmpfs
df -i -x tmpfs -x devtmpfs

echo -e "\n[4/8] Docker Engine, Compose & runc Version (CVE-2025-31133 / 52565 / 52881 check):"
echo "NOTE: runc must be >= 1.2.8 or >= 1.3.3 to mitigate Nov 2025 container escape CVEs."
docker --version || echo "Docker not installed"
docker compose version || echo "Docker Compose v2 plugin not installed"
runc --version || docker info --format '{{json .Runtimes}}' || true

echo -e "\n[5/8] Existing Docker Compose Projects & Running Containers:"
docker compose ls --all || true
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" || true

echo -e "\n[6/8] Existing Docker Networks & Subnets (checking 172.30.0.0/21 availability):"
for net in $(docker network ls --format '{{.Name}}' 2>/dev/null); do
  subnet=$(docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true)
  printf "  %-25s %s\n" "$net" "${subnet:-<no-subnet>}"
done

echo -e "\n[7/8] Host Listening Ports (checking 127.0.0.1:9443 and public bindings):"
ss -tulpn || netstat -tulpn || true

echo -e "\n[8/8] Tailscale & cloudflared Presence (no tokens printed):"
if command -v tailscale >/dev/null 2>&1; then
  tailscale version
  tailscale status --self || true
else
  echo "Tailscale CLI not found on host"
fi

if systemctl is-active --quiet cloudflared 2>/dev/null; then
  echo "Host systemd service 'cloudflared' is ACTIVE"
else
  echo "No active host systemd 'cloudflared' service (checking containers in step 5)"
fi

echo -e "\n=================================================================="
echo " M0 Discovery Complete (Read-Only)."
echo "=================================================================="
