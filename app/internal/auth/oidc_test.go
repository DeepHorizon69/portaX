package auth

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestAEADPreAuthStateAndGroupMapping(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sealer, err := NewAEADSealer(key)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}

	now := time.Now()
	st, challenge, err := GeneratePKCE("cf-sub-1", now)
	if err != nil || challenge == "" {
		t.Fatalf("generate pkce: %v", err)
	}

	sealed, err := sealer.SealState(st)
	if err != nil {
		t.Fatalf("seal state: %v", err)
	}

	opened, err := sealer.OpenState(sealed, now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("open valid state: %v", err)
	}
	if opened.State != st.State || opened.Nonce != st.Nonce || opened.AccessSub != "cf-sub-1" {
		t.Fatalf("unexpected opened state: %+v", opened)
	}

	// Expired pre-auth cookie must fail
	if _, err := sealer.OpenState(sealed, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected expired pre-auth cookie to be rejected")
	}

	// Deny-by-default group mapping tests
	if _, err := MapGroupsToRole([]string{"unrelated-group"}); err == nil {
		t.Fatal("expected unmapped group to be denied")
	}
	role, err := MapGroupsToRole([]string{"portal-users"})
	if err != nil || role != "viewer" {
		t.Fatalf("expected viewer role, got %q (%v)", role, err)
	}
	role, err = MapGroupsToRole([]string{"portal-users", "portal-admins"})
	if err != nil || role != "admin" {
		t.Fatalf("expected admin role, got %q (%v)", role, err)
	}
}
