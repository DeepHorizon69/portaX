package access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrMissingAccessToken = errors.New("missing Cf-Access-Jwt-Assertion header")
	ErrInvalidAccessToken = errors.New("invalid Cloudflare Access JWT")
)

// Identity represents the verified Layer-1 Cloudflare Access identity.
// Note: This proves the request passed Cloudflare Access at the perimeter;
// it NEVER grants application roles inside portaX.
type Identity struct {
	Sub   string
	Email string
	Type  string // "app" (interactive user) or "service-token"
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss        string          `json:"iss"`
	Aud        json.RawMessage `json:"aud"`
	Sub        string          `json:"sub"`
	Email      string          `json:"email"`
	CommonName string          `json:"common_name"`
	Type       string          `json:"type"`
	Exp        int64           `json:"exp"`
	Nbf        int64           `json:"nbf"`
	Iat        int64           `json:"iat"`
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Verifier cryptographically validates Cloudflare Access RS256 JWTs.
type Verifier struct {
	teamDomain string
	audTag     string
	certsURL   string
	httpClient *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	nowFunc   func() time.Time
}

func NewVerifier(teamDomain, audTag string, client *http.Client) *Verifier {
	cleanDomain := strings.TrimRight(strings.TrimSpace(teamDomain), "/")
	if cleanDomain != "" && !strings.HasPrefix(cleanDomain, "http://") && !strings.HasPrefix(cleanDomain, "https://") {
		cleanDomain = "https://" + cleanDomain
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{
		teamDomain: cleanDomain,
		audTag:     strings.TrimSpace(audTag),
		certsURL:   cleanDomain + "/cdn-cgi/access/certs",
		httpClient: client,
		keys:       make(map[string]*rsa.PublicKey),
		nowFunc:    time.Now,
	}
}

// RefreshKeys pre-fetches or refreshes Cloudflare Access public keys into the cache.
func (v *Verifier) RefreshKeys(ctx context.Context) error {
	return v.refreshKeys(ctx)
}

// SetStaticKey registers a public key directly (used in deterministic unit tests).
func (v *Verifier) SetStaticKey(kid string, pub *rsa.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[kid] = pub
	v.fetchedAt = v.nowFunc()
}

// VerifyRequest extracts and verifies Cf-Access-Jwt-Assertion from the HTTP request.
func (v *Verifier) VerifyRequest(ctx context.Context, r *http.Request) (*Identity, error) {
	rawToken := strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion"))
	if rawToken == "" {
		return nil, ErrMissingAccessToken
	}
	return v.VerifyToken(ctx, rawToken)
}

// VerifyToken validates RS256 signature, issuer, audience tag, and expiration.
func (v *Verifier) VerifyToken(ctx context.Context, rawToken string) (*Identity, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed JWT segments", ErrInvalidAccessToken)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header encoding", ErrInvalidAccessToken)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("%w: invalid header JSON", ErrInvalidAccessToken)
	}
	if hdr.Alg != "RS256" || hdr.Kid == "" {
		return nil, fmt.Errorf("%w: unsupported alg %q or empty kid", ErrInvalidAccessToken, hdr.Alg)
	}

	pubKey, err := v.getKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidAccessToken)
	}
	signedInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signedInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidAccessToken)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidAccessToken)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid payload JSON", ErrInvalidAccessToken)
	}

	if strings.TrimRight(claims.Iss, "/") != v.teamDomain {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidAccessToken)
	}
	if !audienceContains(claims.Aud, v.audTag) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidAccessToken)
	}

	now := v.nowFunc().Unix()
	const clockSkew = 30
	if claims.Exp <= now-clockSkew {
		return nil, fmt.Errorf("%w: token expired", ErrInvalidAccessToken)
	}
	if claims.Nbf > 0 && claims.Nbf > now+clockSkew {
		return nil, fmt.Errorf("%w: token not yet valid", ErrInvalidAccessToken)
	}

	sub := claims.Sub
	if sub == "" && claims.CommonName != "" {
		sub = "service-token:" + claims.CommonName
	}
	if sub == "" {
		return nil, fmt.Errorf("%w: empty subject and common_name", ErrInvalidAccessToken)
	}

	return &Identity{
		Sub:   sub,
		Email: claims.Email,
		Type:  claims.Type,
	}, nil
}

func audienceContains(raw json.RawMessage, expected string) bool {
	if expected == "" {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == expected
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, item := range list {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func (v *Verifier) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	pub, ok := v.keys[kid]
	fresh := time.Since(v.fetchedAt) < 1*time.Hour
	v.mu.RUnlock()
	if ok && fresh {
		return pub, nil
	}

	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	pub, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalidAccessToken, kid)
	}
	return pub, nil
}

func (v *Verifier) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch cloudflare certs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare certs status %d", resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64*1024)).Decode(&doc); err != nil {
		return fmt.Errorf("decode cloudflare certs: %w", err)
	}

	parsed := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		eInt := new(big.Int).SetBytes(eBytes).Int64()
		if eInt <= 0 {
			continue
		}
		parsed[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(eInt),
		}
	}

	v.mu.Lock()
	v.keys = parsed
	v.fetchedAt = v.nowFunc()
	v.mu.Unlock()
	return nil
}
