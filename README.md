# portaX — Ultra-Secure, Resilient Homelab Portal (`panel.alsa.web.id`)

Defense-in-depth homelab service portal built with a Go SSR Backend-for-Frontend (`portal`), isolated SSRF-safe health checker (`prober`), 3-listener `Caddy` reverse proxy, `Authentik` (`>= 2025.12.4`), dual isolated `PostgreSQL 17.11` databases, and `Cloudflare Tunnel` + `Cloudflare Access`.

## Key Security Architecture

1. **Two Independent Authentication Layers:**
   - **Layer 1 (Perimeter):** Cloudflare Access (configured with an external IdP such as GitHub/Google with hardware-key MFA, **never** federated to Authentik). Every request to `portal` cryptographically verifies `Cf-Access-Jwt-Assertion` (`RS256`, `iss`, `aud`, `exp`) in [`app/internal/access/jwt.go`](app/internal/access/jwt.go).
   - **Layer 2 (Application Identity & RBAC):** Authentik OIDC Authorization Code + PKCE (`S256`) using a stateless `AES-256-GCM` pre-auth cookie ([`app/internal/auth/oidc.go`](app/internal/auth/oidc.go)) and server-side PostgreSQL sessions storing `HMAC-SHA256(token, pepper)` bound continuously to the Layer-1 `access_sub` ([`app/internal/session/store.go`](app/internal/session/store.go)).
2. **Three Isolated Caddy Listeners ([`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile)):**
   - `:8080` (`net_edge`): Reachable only by `cloudflared` (`172.30.0.2/32`). Enforces a **strict positive path allowlist** on `auth.alsa.web.id` (blocking `/if/admin/*` and `/api/v3/*` admin APIs publicly to mitigate CVE-2026-25227 / CVE-2026-72537).
   - `:8081` (`net_portal`): OIDC back-channel listener for `portal -> authentik` token exchange with **zero** `trusted_proxies`.
   - `127.0.0.1:9443`: Localhost listener for `tailscale serve` administrative access.
3. **Zero-TOCTOU SSRF-Safe Prober ([`app/internal/prober/dialer.go`](app/internal/prober/dialer.go)):**
   - Health check destinations are read-only from Git ([`deploy/prober/targets.yaml`](deploy/prober/targets.yaml)).
   - Validates the resolved socket IP inside `net.Dialer.Control` right before `connect()`, blocking loopback, link-local/metadata (`169.254.0.0/16`), and internal Docker subnets (`172.30.0.0/21`).
   - Runs under the `portal_prober` PostgreSQL role which can only `SELECT/INSERT/UPDATE` on `service_status`.

## Quick Start (Ordered Milestones)

1. **M0 — Read-Only Host Discovery:**
   ```bash
   bash deploy/scripts/m0-discover.sh
   ```
   Confirm `runc >= 1.2.8` (or `1.3.3`) to mitigate CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881, and confirm `>= 3 GB` free RAM.
2. **M1/M2 — Generate Host Secrets & Start Databases:**
   ```bash
   sudo bash deploy/scripts/init-secrets.sh
   cp deploy/.env.example deploy/.env
   docker compose -f deploy/compose.yaml up -d portal-db authentik-db
   ```
3. **M3 — Start Authentik & Tailscale Admin Listener:**
   ```bash
   docker compose -f deploy/compose.yaml up -d authentik-server authentik-worker caddy
   sudo tailscale serve --bg --https=9443 http://127.0.0.1:9443
   ```
4. **M4–M7 — Build & Start Portal, Prober, and Tunnel:**
   ```bash
   docker compose -f deploy/compose.yaml up -d --build portal prober cloudflared
   ```
5. **M8–M9 — Run Backup/Restore Drill & Security Acceptance Suite:**
   ```bash
   sudo bash deploy/scripts/backup.sh
   sudo bash deploy/scripts/restore-verify.sh
   hurl --test --variable base_url=http://172.30.0.3:8080 tests/security/acceptance.hurl
   bash tests/failure/inject-failures.sh
   ```
