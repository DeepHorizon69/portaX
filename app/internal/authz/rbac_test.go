package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEveryRouteHasExplicitSecurityPolicy(t *testing.T) {
	if len(CanonicalRouteTable) == 0 {
		t.Fatal("route table cannot be empty")
	}
	for _, rt := range CanonicalRouteTable {
		if rt.Level == LevelDenyByDefault {
			t.Fatalf("route %s %s has LevelDenyByDefault (must declare explicit policy)", rt.Method, rt.Pattern)
		}
		if rt.Method == http.MethodPost || rt.Method == http.MethodPut || rt.Method == http.MethodDelete {
			if !rt.RequireCSRF {
				t.Fatalf("state-changing route %s %s must require CSRF protection", rt.Method, rt.Pattern)
			}
		}
	}
}

func TestRBACDenyByDefaultAndPrivilegeSeparation(t *testing.T) {
	// Viewer cannot access Admin routes (Acceptance #3 & #13)
	if RoleSatisfies("viewer", LevelAdmin) {
		t.Fatal("viewer must NEVER satisfy LevelAdmin")
	}
	if RoleSatisfies("", LevelViewer) || RoleSatisfies("superadmin-forged", LevelViewer) {
		t.Fatal("unknown or empty role must be denied")
	}
	if !RoleSatisfies("viewer", LevelViewer) {
		t.Fatal("viewer should satisfy LevelViewer")
	}
	if !RoleSatisfies("admin", LevelViewer) || !RoleSatisfies("admin", LevelAdmin) {
		t.Fatal("admin should satisfy viewer and admin levels")
	}
}

func TestCSRFProtection(t *testing.T) {
	domain := "panel.alsa.web.id"
	csrf := "valid-csrf-token-value-123"

	// 1. Valid same-origin POST with matching token succeeds
	reqValid := httptest.NewRequest(http.MethodPost, "https://panel.alsa.web.id/admin/catalog", nil)
	reqValid.Header.Set("Origin", "https://panel.alsa.web.id")
	reqValid.Header.Set("Sec-Fetch-Site", "same-origin")
	reqValid.Header.Set("X-CSRF-Token", csrf)
	if !VerifyCSRF(reqValid, domain, csrf) {
		t.Fatal("expected valid CSRF request to pass")
	}

	// 2. Missing CSRF token fails (Acceptance #7)
	reqMissing := httptest.NewRequest(http.MethodPost, "https://panel.alsa.web.id/admin/catalog", nil)
	reqMissing.Header.Set("Origin", "https://panel.alsa.web.id")
	if VerifyCSRF(reqMissing, domain, csrf) {
		t.Fatal("expected missing CSRF token to be rejected")
	}

	// 3. Cross-origin Origin header fails even with token
	reqEvilOrigin := httptest.NewRequest(http.MethodPost, "https://panel.alsa.web.id/admin/catalog", nil)
	reqEvilOrigin.Header.Set("Origin", "https://attacker.example")
	reqEvilOrigin.Header.Set("X-CSRF-Token", csrf)
	if VerifyCSRF(reqEvilOrigin, domain, csrf) {
		t.Fatal("expected cross-origin request to be rejected")
	}

	// 4. Sec-Fetch-Site: cross-site fails
	reqCrossSite := httptest.NewRequest(http.MethodPost, "https://panel.alsa.web.id/admin/catalog", nil)
	reqCrossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	reqCrossSite.Header.Set("X-CSRF-Token", csrf)
	if VerifyCSRF(reqCrossSite, domain, csrf) {
		t.Fatal("expected Sec-Fetch-Site: cross-site to be rejected")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(60, 3)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !rl.Allow("203.0.113.5", now) {
			t.Fatalf("expected burst request %d to be allowed", i+1)
		}
	}
	if rl.Allow("203.0.113.5", now) {
		t.Fatal("expected 4th immediate request to be rate-limited (Acceptance #8)")
	}
}
