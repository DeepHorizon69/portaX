package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

const (
	// SessionCookieName uses __Host- so browsers enforce Secure, Path=/, and no Domain attribute.
	SessionCookieName = "__Host-portal_session"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session expired")
	ErrAccessBindingFailed = errors.New("session perimeter Access identity mismatch")
)

// Record represents a server-side session stored in PostgreSQL (hashed by HMAC-SHA256).
type Record struct {
	TokenHMAC      []byte
	UserSub        string
	Username       string
	Role           string
	AccessSub      string
	CSRFToken      string
	ClientIP       string
	UserAgent      string
	CreatedAt      time.Time
	LastActivityAt time.Time
	IdleExpiresAt  time.Time
	AbsExpiresAt   time.Time
}

// Repository abstracts PostgreSQL persistence for sessions.
type Repository interface {
	InsertSession(ctx context.Context, rec Record) error
	GetSessionByHMAC(ctx context.Context, tokenHMAC []byte) (*Record, error)
	TouchSession(ctx context.Context, tokenHMAC []byte, lastActivity, newIdleExpires time.Time) error
	DeleteSessionByHMAC(ctx context.Context, tokenHMAC []byte) error
	DeleteSessionsByUserSub(ctx context.Context, userSub string) error
}

type Timeouts struct {
	UserIdle      time.Duration
	UserAbsolute  time.Duration
	AdminIdle     time.Duration
	AdminAbsolute time.Duration
}

// Manager enforces cryptographic session creation, rotation, HMAC hashing,
// idle/absolute timeouts, and continuous Access identity binding.
type Manager struct {
	repo     Repository
	pepper   []byte
	timeouts Timeouts
	nowFunc  func() time.Time
}

func NewManager(repo Repository, pepper []byte, timeouts Timeouts) *Manager {
	return &Manager{
		repo:     repo,
		pepper:   append([]byte(nil), pepper...),
		timeouts: timeouts,
		nowFunc:  time.Now,
	}
}

// ComputeHMAC computes HMAC-SHA256(rawToken, serverPepper) so raw tokens are never stored in PostgreSQL.
func (m *Manager) ComputeHMAC(rawToken string) []byte {
	mac := hmac.New(sha256.New, m.pepper)
	mac.Write([]byte(rawToken))
	return mac.Sum(nil)
}

// IssueNewSession rotates any existing cookie, generates a 256-bit random session ID
// and 256-bit CSRF token, and persists the HMAC digest in the session store.
func (m *Manager) IssueNewSession(ctx context.Context, r *http.Request, userSub, username, role, accessSub, clientIP string) (string, *Record, error) {
	// If the client sent an old session cookie, revoke it server-side (Session Rotation).
	if oldCookie, err := r.Cookie(SessionCookieName); err == nil && oldCookie.Value != "" {
		_ = m.repo.DeleteSessionByHMAC(ctx, m.ComputeHMAC(oldCookie.Value))
	}

	rawToken, err := generateToken(32)
	if err != nil {
		return "", nil, err
	}
	csrfToken, err := generateToken(32)
	if err != nil {
		return "", nil, err
	}

	now := m.nowFunc().UTC()
	idleTTL, absTTL := m.timeoutsForRole(role)

	rec := Record{
		TokenHMAC:      m.ComputeHMAC(rawToken),
		UserSub:        userSub,
		Username:       username,
		Role:           role,
		AccessSub:      accessSub,
		CSRFToken:      csrfToken,
		ClientIP:       clientIP,
		UserAgent:      r.UserAgent(),
		CreatedAt:      now,
		LastActivityAt: now,
		IdleExpiresAt:  now.Add(idleTTL),
		AbsExpiresAt:   now.Add(absTTL),
	}

	if err := m.repo.InsertSession(ctx, rec); err != nil {
		return "", nil, err
	}
	return rawToken, &rec, nil
}

// ValidateAndTouch verifies the session cookie, enforces idle & absolute expiration,
// checks Layer-1 Cloudflare Access identity binding, and slides the idle window
// without ever exceeding AbsExpiresAt.
func (m *Manager) ValidateAndTouch(ctx context.Context, rawToken, currentAccessSub string) (*Record, error) {
	if rawToken == "" {
		return nil, ErrSessionNotFound
	}
	tokenHMAC := m.ComputeHMAC(rawToken)
	rec, err := m.repo.GetSessionByHMAC(ctx, tokenHMAC)
	if err != nil || rec == nil {
		return nil, ErrSessionNotFound
	}

	now := m.nowFunc().UTC()
	if !now.Before(rec.IdleExpiresAt) || !now.Before(rec.AbsExpiresAt) {
		_ = m.repo.DeleteSessionByHMAC(ctx, tokenHMAC)
		return nil, ErrSessionExpired
	}

	// Continuous perimeter-to-session binding (Flaw 3 mitigation)
	if !hmac.Equal([]byte(rec.AccessSub), []byte(currentAccessSub)) {
		_ = m.repo.DeleteSessionByHMAC(ctx, tokenHMAC)
		return nil, ErrAccessBindingFailed
	}

	idleTTL, _ := m.timeoutsForRole(rec.Role)
	newIdle := now.Add(idleTTL)
	if newIdle.After(rec.AbsExpiresAt) {
		newIdle = rec.AbsExpiresAt
	}
	rec.LastActivityAt = now
	rec.IdleExpiresAt = newIdle
	_ = m.repo.TouchSession(ctx, tokenHMAC, now, newIdle)

	return rec, nil
}

// RevokeRequest deletes the session server-side and clears the browser cookie.
func (m *Manager) RevokeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		_ = m.repo.DeleteSessionByHMAC(ctx, m.ComputeHMAC(c.Value))
	}
	ClearSessionCookie(w)
}

func SetSessionCookie(w http.ResponseWriter, rawToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) timeoutsForRole(role string) (time.Duration, time.Duration) {
	if role == "admin" {
		return m.timeouts.AdminIdle, m.timeouts.AdminAbsolute
	}
	return m.timeouts.UserIdle, m.timeouts.UserAbsolute
}

func generateToken(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// InMemoryRepo provides a thread-safe in-memory Repository for unit and acceptance tests.
type InMemoryRepo struct {
	mu   sync.Mutex
	rows map[string]Record
}

func NewInMemoryRepo() *InMemoryRepo {
	return &InMemoryRepo{rows: make(map[string]Record)}
}

func (r *InMemoryRepo) InsertSession(_ context.Context, rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[string(rec.TokenHMAC)] = rec
	return nil
}

func (r *InMemoryRepo) GetSessionByHMAC(_ context.Context, tokenHMAC []byte) (*Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.rows[string(tokenHMAC)]
	if !ok {
		return nil, ErrSessionNotFound
	}
	copyRec := rec
	return &copyRec, nil
}

func (r *InMemoryRepo) TouchSession(_ context.Context, tokenHMAC []byte, lastActivity, newIdleExpires time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.rows[string(tokenHMAC)]
	if !ok {
		return ErrSessionNotFound
	}
	rec.LastActivityAt = lastActivity
	rec.IdleExpiresAt = newIdleExpires
	r.rows[string(tokenHMAC)] = rec
	return nil
}

func (r *InMemoryRepo) DeleteSessionByHMAC(_ context.Context, tokenHMAC []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, string(tokenHMAC))
	return nil
}

func (r *InMemoryRepo) DeleteSessionsByUserSub(_ context.Context, userSub string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range r.rows {
		if v.UserSub == userSub {
			delete(r.rows, k)
		}
	}
	return nil
}
