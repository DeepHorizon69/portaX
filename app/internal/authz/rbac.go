package authz

import (
	"crypto/hmac"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AccessLevel defines the required authorization level for a route.
type AccessLevel int

const (
	LevelDenyByDefault AccessLevel = iota // 0: Unspecified routes ALWAYS fail closed
	LevelHealthzServiceToken
	LevelAuthFlow
	LevelViewer
	LevelAdmin
)

// RoutePolicy declares the mandatory security policy for a route pattern.
type RoutePolicy struct {
	Method      string
	Pattern     string
	Level       AccessLevel
	RequireCSRF bool
}

// CanonicalRouteTable lists every route in the portal application.
// A unit test (TestEveryRouteHasExplicitSecurityPolicy) verifies that zero routes
// have LevelDenyByDefault and all state-changing routes enforce CSRF.
var CanonicalRouteTable = []RoutePolicy{
	{Method: http.MethodGet, Pattern: "/healthz", Level: LevelHealthzServiceToken, RequireCSRF: false},
	{Method: http.MethodGet, Pattern: "/static/", Level: LevelAuthFlow, RequireCSRF: false},
	{Method: http.MethodGet, Pattern: "/auth/login", Level: LevelAuthFlow, RequireCSRF: false},
	{Method: http.MethodGet, Pattern: "/auth/callback", Level: LevelAuthFlow, RequireCSRF: false},
	{Method: http.MethodPost, Pattern: "/auth/logout", Level: LevelViewer, RequireCSRF: true},
	{Method: http.MethodGet, Pattern: "/", Level: LevelViewer, RequireCSRF: false},
	{Method: http.MethodGet, Pattern: "/api/catalog", Level: LevelViewer, RequireCSRF: false},
	{Method: http.MethodGet, Pattern: "/admin", Level: LevelAdmin, RequireCSRF: false},
	{Method: http.MethodPost, Pattern: "/admin/catalog", Level: LevelAdmin, RequireCSRF: true},
	{Method: http.MethodPost, Pattern: "/admin/catalog/delete", Level: LevelAdmin, RequireCSRF: true},
	{Method: http.MethodPost, Pattern: "/admin/sessions/revoke", Level: LevelAdmin, RequireCSRF: true},
	{Method: http.MethodGet, Pattern: "/admin/audit", Level: LevelAdmin, RequireCSRF: false},
}

// RoleSatisfies returns true if the user's server-side session role meets the required level.
// Client headers, query params, or cookies are NEVER consulted for role evaluation.
func RoleSatisfies(userRole string, required AccessLevel) bool {
	switch required {
	case LevelViewer:
		return userRole == "viewer" || userRole == "admin"
	case LevelAdmin:
		return userRole == "admin"
	default:
		return false
	}
}

// VerifyCSRF enforces layered CSRF defenses on state-changing requests (POST/PUT/DELETE/PATCH):
// 1. Fetch Metadata check: rejects cross-site requests via Sec-Fetch-Site.
// 2. Origin header check: if Origin is present, it must match https://<portalDomain>.
// 3. Synchronizer token check: constant-time comparison against the session's CSRFToken.
func VerifyCSRF(r *http.Request, portalDomain, expectedCSRFToken string) bool {
	if expectedCSRFToken == "" {
		return false
	}

	if secFetch := r.Header.Get("Sec-Fetch-Site"); secFetch != "" {
		if secFetch != "same-origin" && secFetch != "none" {
			return false
		}
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		expectedOrigin := "https://" + strings.ToLower(strings.TrimSpace(portalDomain))
		if strings.ToLower(strings.TrimSpace(origin)) != expectedOrigin {
			return false
		}
	}

	provided := r.Header.Get("X-CSRF-Token")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	if provided == "" {
		return false
	}

	return hmac.Equal([]byte(provided), []byte(expectedCSRFToken))
}

// RateLimiter implements a bounded token-bucket rate limiter keyed by client IP or session.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	capacity float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(requestsPerMinute) / 60.0,
		capacity: float64(burst),
	}
}

func (rl *RateLimiter) Allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.buckets) > 4096 {
		// Evict stale entries to bound memory usage
		cutoff := now.Add(-5 * time.Minute)
		for k, b := range rl.buckets {
			if b.last.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
	}

	b, exists := rl.buckets[key]
	if !exists {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, last: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.capacity {
			b.tokens = rl.capacity
		}
		b.last = now
	}

	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}
