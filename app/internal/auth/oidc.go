package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	// PreAuthCookieName uses the __Host- prefix (requires Secure, Path=/, no Domain attribute)
	// to prevent subdomain cookie tossing.
	PreAuthCookieName = "__Host-portal_oidc"
	PreAuthTTL        = 5 * time.Minute
)

var (
	ErrNoMappedRole     = errors.New("authenticated user has no mapped portal role (deny by default)")
	ErrInvalidOIDCState = errors.New("invalid or expired OIDC pre-auth state")
)

// PreAuthState is AEAD-encrypted inside __Host-portal_oidc so unauthenticated
// requests cannot bloat PostgreSQL (Flaw 8 mitigation).
type PreAuthState struct {
	State        string `json:"st"`
	Nonce        string `json:"no"`
	CodeVerifier string `json:"cv"`
	AccessSub    string `json:"as"`
	ExpiresAt    int64  `json:"ex"`
}

// AEADSealer encrypts and authenticates pre-auth OIDC state cookies with AES-256-GCM.
type AEADSealer struct {
	aead cipher.AEAD
}

func NewAEADSealer(key32 []byte) (*AEADSealer, error) {
	if len(key32) != 32 {
		return nil, fmt.Errorf("AEAD key must be 32 bytes, got %d", len(key32))
	}
	block, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AEADSealer{aead: gcm}, nil
}

func (s *AEADSealer) SealState(st PreAuthState) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(PreAuthCookieName))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *AEADSealer) OpenState(encoded string, now time.Time) (*PreAuthState, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidOIDCState
	}
	ns := s.aead.NonceSize()
	if len(raw) <= ns {
		return nil, ErrInvalidOIDCState
	}
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(PreAuthCookieName))
	if err != nil {
		return nil, ErrInvalidOIDCState
	}
	var st PreAuthState
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, ErrInvalidOIDCState
	}
	if now.Unix() > st.ExpiresAt {
		return nil, ErrInvalidOIDCState
	}
	return &st, nil
}

// GeneratePKCE creates a cryptographic state, nonce, PKCE verifier, and S256 challenge.
func GeneratePKCE(accessSub string, now time.Time) (PreAuthState, string, error) {
	state, err := randomBase64URL(24)
	if err != nil {
		return PreAuthState{}, "", err
	}
	nonce, err := randomBase64URL(24)
	if err != nil {
		return PreAuthState{}, "", err
	}
	verifier, err := randomBase64URL(32)
	if err != nil {
		return PreAuthState{}, "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	return PreAuthState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		AccessSub:    accessSub,
		ExpiresAt:    now.Add(PreAuthTTL).Unix(),
	}, challenge, nil
}

func BuildAuthorizeURL(authorizeEndpoint, clientID, redirectURI, state, nonce, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile groups")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return authorizeEndpoint + "?" + q.Encode()
}

// ClearPreAuthCookie overwrites and expires the pre-auth OIDC cookie during session rotation.
func ClearPreAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     PreAuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// MapGroupsToRole enforces deny-by-default group mapping from Authentik groups to portaX roles.
// Unknown groups are ignored; if neither 'portal-admins' nor 'portal-users' is present,
// access is denied with ErrNoMappedRole.
func MapGroupsToRole(groups []string) (string, error) {
	hasViewer := false
	for _, g := range groups {
		switch g {
		case "portal-admins":
			return "admin", nil
		case "portal-users":
			hasViewer = true
		}
	}
	if hasViewer {
		return "viewer", nil
	}
	return "", ErrNoMappedRole
}

func randomBase64URL(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
