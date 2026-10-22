package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRotationExpiryAndRevocation(t *testing.T) {
	repo := NewInMemoryRepo()
	mgr := NewManager(repo, []byte("0123456789abcdef0123456789abcdef"), Timeouts{
		UserIdle:      30 * time.Minute,
		UserAbsolute:  12 * time.Hour,
		AdminIdle:     10 * time.Minute,
		AdminAbsolute: 1 * time.Hour,
	})

	now := time.Now().UTC()
	mgr.nowFunc = func() time.Time { return now }

	// 1. Issue first session
	req1 := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	tok1, rec1, err := mgr.IssueNewSession(context.Background(), req1, "sub-1", "alsa", "viewer", "cf-sub-1", "198.51.100.1")
	if err != nil || tok1 == "" || rec1 == nil {
		t.Fatalf("issue session 1: %v", err)
	}

	// 2. Rotate session on re-authentication (Acceptance #4)
	req2 := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req2.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok1})
	tok2, _, err := mgr.IssueNewSession(context.Background(), req2, "sub-1", "alsa-admin", "admin", "cf-sub-1", "198.51.100.1")
	if err != nil {
		t.Fatalf("issue rotated session: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("session token was not rotated")
	}
	if _, err := mgr.ValidateAndTouch(context.Background(), tok1, "cf-sub-1"); err == nil {
		t.Fatal("expected rotated-out session token to be invalidated")
	}

	// 3. Perimeter Access identity mismatch must revoke session (Flaw 3)
	if _, err := mgr.ValidateAndTouch(context.Background(), tok2, "different-cf-sub"); err == nil {
		t.Fatal("expected mismatched Access identity to fail session validation")
	}

	// 4. Issue fresh session and verify idle timeout expiration (Acceptance #6)
	tok3, _, _ := mgr.IssueNewSession(context.Background(), req1, "sub-1", "alsa-admin", "admin", "cf-sub-1", "198.51.100.1")
	now = now.Add(11 * time.Minute) // exceeds 10m admin idle timeout
	if _, err := mgr.ValidateAndTouch(context.Background(), tok3, "cf-sub-1"); err == nil {
		t.Fatal("expected idle-expired admin session to be rejected")
	}

	// 5. Server-side revocation on logout (Acceptance #5)
	tok4, _, _ := mgr.IssueNewSession(context.Background(), req1, "sub-1", "alsa", "viewer", "cf-sub-1", "198.51.100.1")
	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok4})
	w := httptest.NewRecorder()
	mgr.RevokeRequest(context.Background(), w, logoutReq)

	if _, err := mgr.ValidateAndTouch(context.Background(), tok4, "cf-sub-1"); err == nil {
		t.Fatal("expected logged-out session to be invalid on server")
	}
}
