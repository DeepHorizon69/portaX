package audit

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLoggerRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, nil)

	logger.Log(context.Background(), Event{
		EventType:      "auth_callback",
		ActorSub:       "sub-123",
		ActorUsername:  "alsa",
		ActorRole:      "viewer",
		AccessIdentity: "alsa@example.com",
		ClientIP:       "203.0.113.10",
		TargetResource: "/auth/callback",
		Outcome:        "success",
		Metadata: map[string]string{
			"password":                "super-secret-password-123",
			"session_token":           "raw-session-token-value",
			"Cf-Access-Jwt-Assertion": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret",
			"oidc_code_verifier":      "pkce-secret-verifier",
			"auth_method":             "webauthn",
		},
	})

	output := buf.String()
	forbidden := []string{
		"super-secret-password-123",
		"raw-session-token-value",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret",
		"pkce-secret-verifier",
	}
	for _, secret := range forbidden {
		if strings.Contains(output, secret) {
			t.Fatalf("security log leaked secret %q in output: %s", secret, output)
		}
	}
	if !strings.Contains(output, `"auth_method":"webauthn"`) {
		t.Fatalf("expected non-sensitive metadata to be preserved, got: %s", output)
	}
}
