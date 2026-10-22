# ==============================================================================
# portaX Automated Negative Security & Acceptance Test Suite (Hurl)
# ==============================================================================
# Usage:
#   hurl --test --variable base_url=http://172.30.0.3:8080 tests/security/acceptance.hurl
# ==============================================================================

# ------------------------------------------------------------------------------
# Test 1 & 9: Direct request to Portal without Cloudflare Access JWT MUST return 403
#             and leak ZERO catalog data or stack traces.
# ------------------------------------------------------------------------------
GET {{base_url}}/
Host: panel.alsa.web.id
HTTP 403
[Asserts]
header "Cache-Control" == "no-store"
header "X-Content-Type-Options" == "nosniff"
header "X-Frame-Options" == "DENY"
body not contains "pihole"
body not contains "proxmox"
body not contains "goroutine"

# ------------------------------------------------------------------------------
# Test 1b: Protected JSON API without Cloudflare Access JWT MUST return 403
# ------------------------------------------------------------------------------
GET {{base_url}}/api/catalog
Host: panel.alsa.web.id
HTTP 403
[Asserts]
body not contains "launch_url"

# ------------------------------------------------------------------------------
# Test 3 & 13: Admin route with forged client-side role headers MUST return 403
# ------------------------------------------------------------------------------
POST {{base_url}}/admin/catalog
Host: panel.alsa.web.id
X-Role: admin
X-Forwarded-User: akadmin
Cookie: __Host-portal_session=forged-admin-cookie-value
HTTP 403

# ------------------------------------------------------------------------------
# Test 10a: Public Authentik /if/admin/ path MUST be blocked (404) at Caddy
# ------------------------------------------------------------------------------
GET {{base_url}}/if/admin/
Host: auth.alsa.web.id
HTTP 404

# ------------------------------------------------------------------------------
# Test 10b: Public Authentik /api/v3/propertymappings/ (CVE-2026-25227 vector)
#           MUST be blocked (404) at Caddy on the public hostname
# ------------------------------------------------------------------------------
GET {{base_url}}/api/v3/propertymappings/all/
Host: auth.alsa.web.id
HTTP 404

# ------------------------------------------------------------------------------
# Test 10c: Public Authentik /api/v3/core/users/ MUST be blocked (404) at Caddy
# ------------------------------------------------------------------------------
GET {{base_url}}/api/v3/core/users/
Host: auth.alsa.web.id
HTTP 404

# ------------------------------------------------------------------------------
# Test 10d: Unknown Host header on Caddy :8080 MUST return 404
# ------------------------------------------------------------------------------
GET {{base_url}}/
Host: unknown.alsa.web.id
HTTP 404
