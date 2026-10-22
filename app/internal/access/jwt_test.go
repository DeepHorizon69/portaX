package access

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func signTestJWT(t *testing.T, priv *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	hdrJSON, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAccessJWTVerifier(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}

	teamDomain := "https://alsa.cloudflareaccess.com"
	audTag := "aud-tag-123456"
	v := NewVerifier(teamDomain, audTag, nil)
	v.SetStaticKey("kid-1", &priv.PublicKey)

	now := time.Now()
	validToken := signTestJWT(t, priv, "kid-1", "RS256", map[string]any{
		"iss":   teamDomain,
		"aud":   []string{audTag},
		"sub":   "cf-user-uuid-1",
		"email": "alsa@alsa.web.id",
		"exp":   now.Add(10 * time.Minute).Unix(),
	})

	id, err := v.VerifyToken(context.Background(), validToken)
	if err != nil {
		t.Fatalf("expected valid token to succeed, got: %v", err)
	}
	if id.Sub != "cf-user-uuid-1" || id.Email != "alsa@alsa.web.id" {
		t.Fatalf("unexpected identity: %+v", id)
	}

	// Wrong Audience Tag must fail (Acceptance #9)
	wrongAudToken := signTestJWT(t, priv, "kid-1", "RS256", map[string]any{
		"iss": teamDomain,
		"aud": []string{"other-app-aud"},
		"sub": "cf-user-uuid-1",
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if _, err := v.VerifyToken(context.Background(), wrongAudToken); err == nil {
		t.Fatal("expected token with wrong AUD to be rejected")
	}

	// Expired token must fail
	expiredToken := signTestJWT(t, priv, "kid-1", "RS256", map[string]any{
		"iss": teamDomain,
		"aud": []string{audTag},
		"sub": "cf-user-uuid-1",
		"exp": now.Add(-5 * time.Minute).Unix(),
	})
	if _, err := v.VerifyToken(context.Background(), expiredToken); err == nil {
		t.Fatal("expected expired Access token to be rejected")
	}
}
