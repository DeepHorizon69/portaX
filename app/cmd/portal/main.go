package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alsa/portax/internal/access"
	"github.com/alsa/portax/internal/audit"
	"github.com/alsa/portax/internal/auth"
	"github.com/alsa/portax/internal/authz"
	"github.com/alsa/portax/internal/catalog"
	"github.com/alsa/portax/internal/db"
	"github.com/alsa/portax/internal/prober"
	"github.com/alsa/portax/internal/session"
	"gopkg.in/yaml.v3"
)

type opsStatus struct {
	CollectedAt     string `json:"collected_at"`
	DiskUsedPercent int    `json:"disk_used_percent"`
	MemAvailableMB  int    `json:"mem_available_mb"`
	Load1M          string `json:"load_1m"`
	LastBackupUTC   string `json:"last_backup_utc"`
}

type targetsConfig struct {
	Targets []prober.Target `yaml:"targets"`
}

type oidcTokenResponse struct {
	IDToken string `json:"id_token"`
}

type oidcIDTokenClaims struct {
	Iss               string   `json:"iss"`
	Aud               any      `json:"aud"`
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Nonce             string   `json:"nonce"`
	Exp               int64    `json:"exp"`
}

type portalServer struct {
	portalDomain        string
	authDomain          string
	trustedProxyIP      string
	oidcIssuerURL       string
	oidcInternalBaseURL string
	oidcClientID        string
	oidcClientSecret    string
	oidcRedirectURL     string
	allowedSuffixes     []string
	validProbeTargets   map[string]bool
	opsStatusFile       string

	accessVerifier *access.Verifier
	oidcSealer     *auth.AEADSealer
	sessions       *session.Manager
	store          *db.Store
	auditor        *audit.Logger
	generalLimiter *authz.RateLimiter
	adminLimiter   *authz.RateLimiter
	templates      *template.Template
	httpClient     *http.Client
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	auditor := audit.NewLogger(os.Stdout, nil)

	dbHost := envOr("DB_HOST", "172.30.3.4")
	dbPort := envOr("DB_PORT", "5432")
	dbName := envOr("DB_NAME", "portax")

	// 1. Run schema migrations using portal_migrator role on startup
	migratorUser := envOr("DB_MIGRATOR_USER", "portal_migrator")
	migratorPassFile := envOr("DB_MIGRATOR_PASSWORD_FILE", "/run/secrets/portal_db_migrator_password")
	migStore, err := db.ConnectPool(ctx, dbHost, dbPort, dbName, migratorUser, migratorPassFile, 2)
	if err != nil {
		os.Exit(1)
	}
	if err := migStore.ExecMigrationFile(ctx, "/app/migrations/001_init.sql"); err != nil {
		migStore.Close()
		os.Exit(1)
	}
	migStore.Close()

	// 2. Connect runtime pool using least-privilege portal_app role (no DDL, no DELETE on audit_logs)
	appUser := envOr("DB_USER", "portal_app")
	appPassFile := envOr("DB_PASSWORD_FILE", "/run/secrets/portal_db_app_password")
	store, err := db.ConnectPool(ctx, dbHost, dbPort, dbName, appUser, appPassFile, 15)
	if err != nil {
		os.Exit(1)
	}
	defer store.Close()

	auditor = audit.NewLogger(os.Stdout, store)

	pepperBytes := mustReadHexKey(envOr("SESSION_PEPPER_FILE", "/run/secrets/portal_session_pepper"), 32)
	aeadKeyBytes := mustReadHexKey(envOr("COOKIE_AEAD_KEY_FILE", "/run/secrets/portal_cookie_aead_key"), 32)
	oidcSecret := mustReadSecretString(envOr("OIDC_CLIENT_SECRET_FILE", "/run/secrets/portal_oidc_client_secret"))

	sealer, err := auth.NewAEADSealer(aeadKeyBytes)
	if err != nil {
		os.Exit(1)
	}

	timeouts := session.Timeouts{
		UserIdle:      mustDuration(envOr("SESSION_USER_IDLE_TIMEOUT", "30m")),
		UserAbsolute:  mustDuration(envOr("SESSION_USER_ABSOLUTE_TIMEOUT", "12h")),
		AdminIdle:     mustDuration(envOr("SESSION_ADMIN_IDLE_TIMEOUT", "10m")),
		AdminAbsolute: mustDuration(envOr("SESSION_ADMIN_ABSOLUTE_TIMEOUT", "1h")),
	}

	validTargets := loadValidProbeTargets(envOr("TARGETS_FILE", "/etc/portax/targets.yaml"))
	tmpl := template.Must(template.ParseGlob("/app/web/templates/*.html"))

	srv := &portalServer{
		portalDomain:        envOr("PORTAL_DOMAIN", "panel.alsa.web.id"),
		authDomain:          envOr("AUTH_DOMAIN", "auth.alsa.web.id"),
		trustedProxyIP:      envOr("TRUSTED_PROXY_IP", "172.30.1.2"),
		oidcIssuerURL:       envOr("OIDC_ISSUER_URL", "https://auth.alsa.web.id/application/o/portax/"),
		oidcInternalBaseURL: strings.TrimRight(envOr("OIDC_INTERNAL_BASE_URL", "http://172.30.1.2:8081/application/o/portax"), "/"),
		oidcClientID:        envOr("OIDC_CLIENT_ID", "portax-confidential-client"),
		oidcClientSecret:    oidcSecret,
		oidcRedirectURL:     envOr("OIDC_REDIRECT_URL", "https://panel.alsa.web.id/auth/callback"),
		allowedSuffixes:     strings.Split(envOr("ALLOWED_LAUNCH_HOST_SUFFIXES", "alsa.web.id,ts.net"), ","),
		validProbeTargets:   validTargets,
		opsStatusFile:       envOr("OPS_STATUS_FILE", "/var/run/portax-ops/status.json"),
		accessVerifier:      access.NewVerifier(os.Getenv("CF_ACCESS_TEAM_DOMAIN"), os.Getenv("CF_ACCESS_AUD_TAG"), nil),
		oidcSealer:          sealer,
		sessions:            session.NewManager(store, pepperBytes, timeouts),
		store:               store,
		auditor:             auditor,
		generalLimiter:      authz.NewRateLimiter(60, 20),
		adminLimiter:        authz.NewRateLimiter(10, 5),
		templates:           tmpl,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
	}

	httpSrv := &http.Server{
		Addr:              envOr("LISTEN_ADDR", "0.0.0.0:8000"),
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	_ = httpSrv.ListenAndServe()
}

func (s *portalServer) routes() http.Handler {
	mux := http.NewServeMux()
	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir("/app/web/static")))

	mux.HandleFunc("/healthz", s.withSecurity(authz.LevelHealthzServiceToken, false, s.handleHealthz))
	mux.HandleFunc("/static/", s.withSecurity(authz.LevelAuthFlow, false, func(w http.ResponseWriter, r *http.Request, _ *access.Identity, _ *session.Record) {
		fileServer.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/auth/login", s.withSecurity(authz.LevelAuthFlow, false, s.handleLogin))
	mux.HandleFunc("/auth/callback", s.withSecurity(authz.LevelAuthFlow, false, s.handleCallback))
	mux.HandleFunc("/auth/logout", s.withSecurity(authz.LevelViewer, true, s.handleLogout))
	mux.HandleFunc("/", s.withSecurity(authz.LevelViewer, false, s.handleDashboard))
	mux.HandleFunc("/api/catalog", s.withSecurity(authz.LevelViewer, false, s.handleCatalogJSON))
	mux.HandleFunc("/admin", s.withSecurity(authz.LevelAdmin, false, s.handleAdminPage))
	mux.HandleFunc("/admin/catalog", s.withSecurity(authz.LevelAdmin, true, s.handleAdminSaveCatalog))
	mux.HandleFunc("/admin/catalog/delete", s.withSecurity(authz.LevelAdmin, true, s.handleAdminDeleteCatalog))

	return mux
}

type authedHandler func(w http.ResponseWriter, r *http.Request, accessID *access.Identity, sess *session.Record)

// withSecurity enforces the mandatory defense-in-depth middleware chain on every route:
// 1. Peer IP check (must come from Caddy on net_portal).
// 2. Host header validation (must match PORTAL_DOMAIN).
// 3. Layer-1 Cloudflare Access JWT verification (RS256 + AUD + exp).
// 4. Token-bucket rate limiting.
// 5. Layer-2 Server-side Session verification + continuous Access identity binding.
// 6. Deny-by-default RBAC check.
// 7. Synchronizer token + Origin/Sec-Fetch-Site CSRF protection on state-changing requests.
func (s *portalServer) withSecurity(level authz.AccessLevel, requireCSRF bool, next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if s.trustedProxyIP != "" && peerIP != s.trustedProxyIP {
			s.renderError(w, http.StatusForbidden, "Forbidden", "Untrusted network peer.", false)
			return
		}

		if !strings.EqualFold(r.Host, s.portalDomain) {
			s.renderError(w, http.StatusMisdirectedRequest, "Invalid Host", "Unexpected Host header.", false)
			return
		}

		clientIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if clientIP == "" {
			clientIP = peerIP
		}

		if !s.generalLimiter.Allow(clientIP, time.Now()) {
			s.renderError(w, http.StatusTooManyRequests, "Rate Limited", "Too many requests. Please wait.", false)
			return
		}

		// Layer 1: Verify Cloudflare Access JWT on EVERY request (including /healthz)
		accessID, err := s.accessVerifier.VerifyRequest(r.Context(), r)
		if err != nil {
			s.auditor.Log(r.Context(), audit.Event{
				EventType:      "access_jwt_rejected",
				ClientIP:       clientIP,
				TargetResource: r.URL.Path,
				Outcome:        "denied",
			})
			s.renderError(w, http.StatusForbidden, "Perimeter Access Required", "Valid Cloudflare Access assertion is required.", false)
			return
		}

		if level == authz.LevelHealthzServiceToken || level == authz.LevelAuthFlow {
			next(w, r, accessID, nil)
			return
		}

		// Layer 2: Verify server-side session from PostgreSQL
		cookie, err := r.Cookie(session.SessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		sess, err := s.sessions.ValidateAndTouch(r.Context(), cookie.Value, accessID.Sub)
		if err != nil {
			session.ClearSessionCookie(w)
			if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrSessionExpired) || errors.Is(err, session.ErrAccessBindingFailed) {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
				return
			}
			// Database failure -> Fail closed with clean 503 (Acceptance #11)
			s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Session store is temporarily unreachable.", false)
			return
		}

		// Enforce Deny-by-Default RBAC (Acceptance #3 & #13)
		if !authz.RoleSatisfies(sess.Role, level) {
			s.auditor.Log(r.Context(), audit.Event{
				EventType:      "authz_denied",
				ActorSub:       sess.UserSub,
				ActorUsername:  sess.Username,
				ActorRole:      sess.Role,
				AccessIdentity: accessID.Email,
				ClientIP:       clientIP,
				TargetResource: r.URL.Path,
				Outcome:        "denied",
			})
			s.renderError(w, http.StatusForbidden, "Access Denied", "Your account does not have permission for this resource.", false)
			return
		}

		// Enforce CSRF & Admin rate limits on state-changing requests (Acceptance #7 & #8)
		if requireCSRF {
			if r.Method != http.MethodPost {
				s.renderError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST required.", false)
				return
			}
			if level == authz.LevelAdmin && !s.adminLimiter.Allow(sess.UserSub, time.Now()) {
				s.renderError(w, http.StatusTooManyRequests, "Rate Limited", "Admin rate limit exceeded.", false)
				return
			}
			if !authz.VerifyCSRF(r, s.portalDomain, sess.CSRFToken) {
				s.auditor.Log(r.Context(), audit.Event{
					EventType:      "csrf_rejected",
					ActorSub:       sess.UserSub,
					ActorUsername:  sess.Username,
					ActorRole:      sess.Role,
					AccessIdentity: accessID.Email,
					ClientIP:       clientIP,
					TargetResource: r.URL.Path,
					Outcome:        "denied",
				})
				s.renderError(w, http.StatusForbidden, "CSRF Verification Failed", "Invalid or missing CSRF token.", false)
				return
			}
		}

		next(w, r, accessID, sess)
	}
}

func (s *portalServer) handleHealthz(w http.ResponseWriter, r *http.Request, _ *access.Identity, _ *session.Record) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *portalServer) handleLogin(w http.ResponseWriter, r *http.Request, accessID *access.Identity, _ *session.Record) {
	now := time.Now().UTC()
	st, challenge, err := auth.GeneratePKCE(accessID.Sub, now)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Login Error", "Could not initialize authentication flow.", false)
		return
	}
	sealed, err := s.oidcSealer.SealState(st)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Login Error", "Could not seal authentication state.", false)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.PreAuthCookieName,
		Value:    sealed,
		Path:     "/",
		MaxAge:   int(auth.PreAuthTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	authorizeEndpoint := "https://" + s.authDomain + "/application/o/authorize/"
	redirectURL := auth.BuildAuthorizeURL(authorizeEndpoint, s.oidcClientID, s.oidcRedirectURL, st.State, st.Nonce, challenge)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *portalServer) handleCallback(w http.ResponseWriter, r *http.Request, accessID *access.Identity, _ *session.Record) {
	clientIP := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	preCookie, err := r.Cookie(auth.PreAuthCookieName)
	if err != nil || preCookie.Value == "" {
		s.renderError(w, http.StatusBadRequest, "Authentication Error", "Missing pre-authentication state cookie.", false)
		return
	}
	// Always clear pre-auth cookie immediately (one-time use / Session Rotation)
	auth.ClearPreAuthCookie(w)

	st, err := s.oidcSealer.OpenState(preCookie.Value, time.Now().UTC())
	if err != nil || st.AccessSub != accessID.Sub {
		s.renderError(w, http.StatusBadRequest, "Authentication Error", "Invalid or expired OIDC state.", false)
		return
	}

	if r.URL.Query().Get("state") != st.State {
		s.renderError(w, http.StatusBadRequest, "Authentication Error", "OIDC state mismatch.", false)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.renderError(w, http.StatusBadRequest, "Authentication Error", "Missing authorization code.", false)
		return
	}

	// Back-channel token exchange via Caddy :8081 internal listener
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", s.oidcClientID)
	form.Set("client_secret", s.oidcClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", s.oidcRedirectURL)
	form.Set("code_verifier", st.CodeVerifier)

	tokenEndpoint := "http://172.30.1.2:8081/application/o/token/"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		s.renderError(w, http.StatusBadGateway, "Authentication Error", "Identity provider unavailable.", false)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		s.auditor.Log(r.Context(), audit.Event{
			EventType:      "login_failed",
			AccessIdentity: accessID.Email,
			ClientIP:       clientIP,
			TargetResource: "/auth/callback",
			Outcome:        "failure",
		})
		s.renderError(w, http.StatusUnauthorized, "Authentication Rejected", "Token exchange failed.", false)
		return
	}
	defer resp.Body.Close()

	var tokResp oidcTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32*1024)).Decode(&tokResp); err != nil || tokResp.IDToken == "" {
		s.renderError(w, http.StatusUnauthorized, "Authentication Rejected", "Invalid token response.", false)
		return
	}

	claims, err := parseAndValidateIDToken(tokResp.IDToken, s.oidcIssuerURL, st.Nonce)
	if err != nil {
		s.renderError(w, http.StatusUnauthorized, "Authentication Rejected", "ID token verification failed.", false)
		return
	}

	role, err := auth.MapGroupsToRole(claims.Groups)
	if err != nil {
		s.auditor.Log(r.Context(), audit.Event{
			EventType:      "authz_no_mapped_role",
			ActorSub:       claims.Sub,
			ActorUsername:  claims.PreferredUsername,
			AccessIdentity: accessID.Email,
			ClientIP:       clientIP,
			TargetResource: "/auth/callback",
			Outcome:        "denied",
		})
		s.renderError(w, http.StatusForbidden, "Access Denied", "Your identity is not assigned to an authorized portal group.", true)
		return
	}

	rawSessionToken, _, err := s.sessions.IssueNewSession(r.Context(), r, claims.Sub, claims.PreferredUsername, role, accessID.Sub, clientIP)
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Could not persist session.", false)
		return
	}
	session.SetSessionCookie(w, rawSessionToken)

	s.auditor.Log(r.Context(), audit.Event{
		EventType:      "login_success",
		ActorSub:       claims.Sub,
		ActorUsername:  claims.PreferredUsername,
		ActorRole:      role,
		AccessIdentity: accessID.Email,
		ClientIP:       clientIP,
		TargetResource: "/auth/callback",
		Outcome:        "success",
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *portalServer) handleLogout(w http.ResponseWriter, r *http.Request, accessID *access.Identity, sess *session.Record) {
	s.sessions.RevokeRequest(r.Context(), w, r)
	s.auditor.Log(r.Context(), audit.Event{
		EventType:      "logout",
		ActorSub:       sess.UserSub,
		ActorUsername:  sess.Username,
		ActorRole:      sess.Role,
		AccessIdentity: accessID.Email,
		ClientIP:       sess.ClientIP,
		TargetResource: "/auth/logout",
		Outcome:        "success",
	})
	s.renderError(w, http.StatusOK, "Signed Out", "Your portal session has been revoked server-side.", true)
}

func (s *portalServer) handleDashboard(w http.ResponseWriter, r *http.Request, accessID *access.Identity, sess *session.Record) {
	if r.URL.Path != "/" {
		s.renderError(w, http.StatusNotFound, "Not Found", "Page not found.", false)
		return
	}
	allItems, err := s.store.ListCatalogWithStatus(r.Context())
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Database is temporarily unreachable.", false)
		return
	}
	visible := catalog.FilterForRole(allItems, sess.Role)

	data := map[string]any{
		"Username":          sess.Username,
		"Role":              sess.Role,
		"AccessEmail":       accessID.Email,
		"CSRFToken":         sess.CSRFToken,
		"SessionAbsExpires": sess.AbsExpiresAt.Format("15:04 UTC"),
		"Services":          visible,
		"OpsStatus":         s.readOpsStatus(),
	}
	_ = s.templates.ExecuteTemplate(w, "dashboard.html", data)
}

func (s *portalServer) handleCatalogJSON(w http.ResponseWriter, r *http.Request, _ *access.Identity, sess *session.Record) {
	allItems, err := s.store.ListCatalogWithStatus(r.Context())
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Database unreachable.", false)
		return
	}
	visible := catalog.FilterForRole(allItems, sess.Role)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(visible)
}

func (s *portalServer) handleAdminPage(w http.ResponseWriter, r *http.Request, _ *access.Identity, sess *session.Record) {
	items, err := s.store.ListCatalogWithStatus(r.Context())
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Database unreachable.", false)
		return
	}
	events, err := s.store.ListRecentAuditEvents(r.Context(), 50)
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Database unreachable.", false)
		return
	}
	data := map[string]any{
		"Username":    sess.Username,
		"CSRFToken":   sess.CSRFToken,
		"Services":    items,
		"AuditEvents": events,
	}
	_ = s.templates.ExecuteTemplate(w, "admin.html", data)
}

func (s *portalServer) handleAdminSaveCatalog(w http.ResponseWriter, r *http.Request, accessID *access.Identity, sess *session.Record) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "Invalid Form", "Malformed form submission.", false)
		return
	}

	roles := []string{"admin"}
	if r.FormValue("visibility") == "viewer_and_admin" {
		roles = []string{"viewer", "admin"}
	}

	item := catalog.Item{
		ID:              strings.TrimSpace(r.FormValue("id")),
		DisplayName:     strings.TrimSpace(r.FormValue("display_name")),
		Description:     strings.TrimSpace(r.FormValue("description")),
		Category:        strings.TrimSpace(r.FormValue("category")),
		IconKey:         strings.TrimSpace(r.FormValue("icon_key")),
		LaunchURL:       strings.TrimSpace(r.FormValue("launch_url")),
		ProtectionMode:  strings.TrimSpace(r.FormValue("protection_mode")),
		AllowedRoles:    roles,
		ProbeTargetID:   strings.TrimSpace(r.FormValue("probe_target_id")),
		MaintenanceMode: r.FormValue("maintenance_mode") == "true",
		MaintenanceNote: strings.TrimSpace(r.FormValue("maintenance_note")),
	}

	if err := catalog.ValidateItem(item, s.allowedSuffixes, s.validProbeTargets); err != nil {
		s.renderError(w, http.StatusBadRequest, "Validation Failed", err.Error(), false)
		return
	}

	if err := s.store.UpsertCatalogItem(r.Context(), item, sess.Username); err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Database Error", "Could not save catalog item.", false)
		return
	}

	s.auditor.Log(r.Context(), audit.Event{
		EventType:      "catalog_upsert",
		ActorSub:       sess.UserSub,
		ActorUsername:  sess.Username,
		ActorRole:      sess.Role,
		AccessIdentity: accessID.Email,
		ClientIP:       sess.ClientIP,
		TargetResource: "/admin/catalog/" + item.ID,
		Outcome:        "success",
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *portalServer) handleAdminDeleteCatalog(w http.ResponseWriter, r *http.Request, accessID *access.Identity, sess *session.Record) {
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		s.renderError(w, http.StatusBadRequest, "Validation Failed", "Missing service id.", false)
		return
	}
	if err := s.store.DeleteCatalogItem(r.Context(), id); err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Database Error", "Could not delete catalog item.", false)
		return
	}
	s.auditor.Log(r.Context(), audit.Event{
		EventType:      "catalog_delete",
		ActorSub:       sess.UserSub,
		ActorUsername:  sess.Username,
		ActorRole:      sess.Role,
		AccessIdentity: accessID.Email,
		ClientIP:       sess.ClientIP,
		TargetResource: "/admin/catalog/" + id,
		Outcome:        "success",
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *portalServer) renderError(w http.ResponseWriter, code int, title, message string, showLogout bool) {
	w.WriteHeader(code)
	_ = s.templates.ExecuteTemplate(w, "error.html", map[string]any{
		"Code":       code,
		"Title":      title,
		"Message":    message,
		"ShowLogout": showLogout,
	})
}

func (s *portalServer) readOpsStatus() *opsStatus {
	raw, err := os.ReadFile(s.opsStatusFile)
	if err != nil {
		return nil
	}
	var st opsStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil
	}
	return &st
}

func parseAndValidateIDToken(idToken, expectedIssuer, expectedNonce string) (*oidcIDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims oidcIDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if strings.TrimRight(claims.Iss, "/") != strings.TrimRight(expectedIssuer, "/") {
		return nil, errors.New("id_token issuer mismatch")
	}
	if claims.Nonce == "" || claims.Nonce != expectedNonce {
		return nil, errors.New("id_token nonce mismatch")
	}
	if claims.Exp <= time.Now().Unix()-30 {
		return nil, errors.New("id_token expired")
	}
	if claims.Sub == "" {
		return nil, errors.New("empty sub")
	}
	return &claims, nil
}

func loadValidProbeTargets(path string) map[string]bool {
	out := make(map[string]bool)
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var cfg targetsConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return out
	}
	for _, t := range cfg.Targets {
		if t.ID != "" {
			out[t.ID] = true
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func mustReadSecretString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		os.Exit(1)
	}
	return strings.TrimSpace(string(b))
}

func mustReadHexKey(path string, numBytes int) []byte {
	s := mustReadSecretString(path)
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) < numBytes {
		os.Exit(1)
	}
	return decoded[:numBytes]
}

func mustDuration(val string) time.Duration {
	d, err := time.ParseDuration(val)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}
