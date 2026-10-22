package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alsa/portax/internal/audit"
	"github.com/alsa/portax/internal/catalog"
	"github.com/alsa/portax/internal/prober"
	"github.com/alsa/portax/internal/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps a bounded pgxpool.Pool for PostgreSQL operations.
type Store struct {
	pool *pgxpool.Pool
}

func ConnectPool(ctx context.Context, host, port, dbName, user, passwordFile string, maxConns int32) (*Store, error) {
	passBytes, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("read db password file: %w", err)
	}
	password := strings.TrimSpace(string(passBytes))

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		url.QueryEscape(user),
		url.QueryEscape(password),
		host,
		port,
		url.QueryEscape(dbName),
	)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) ExecMigrationFile(ctx context.Context, sqlFilePath string) error {
	sqlBytes, err := os.ReadFile(sqlFilePath)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, string(sqlBytes))
	return err
}

// --- Session Repository Implementation ---

func (s *Store) InsertSession(ctx context.Context, rec session.Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (
			token_hmac, user_sub, username, role, access_sub, csrf_token,
			client_ip, user_agent, created_at, last_activity_at, idle_expires_at, abs_expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`,
		rec.TokenHMAC, rec.UserSub, rec.Username, rec.Role, rec.AccessSub, rec.CSRFToken,
		rec.ClientIP, rec.UserAgent, rec.CreatedAt, rec.LastActivityAt, rec.IdleExpiresAt, rec.AbsExpiresAt,
	)
	return err
}

func (s *Store) GetSessionByHMAC(ctx context.Context, tokenHMAC []byte) (*session.Record, error) {
	var rec session.Record
	err := s.pool.QueryRow(ctx, `
		SELECT token_hmac, user_sub, username, role, access_sub, csrf_token,
		       client_ip, user_agent, created_at, last_activity_at, idle_expires_at, abs_expires_at
		FROM sessions
		WHERE token_hmac = $1
	`, tokenHMAC).Scan(
		&rec.TokenHMAC, &rec.UserSub, &rec.Username, &rec.Role, &rec.AccessSub, &rec.CSRFToken,
		&rec.ClientIP, &rec.UserAgent, &rec.CreatedAt, &rec.LastActivityAt, &rec.IdleExpiresAt, &rec.AbsExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, session.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) TouchSession(ctx context.Context, tokenHMAC []byte, lastActivity, newIdleExpires time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions
		SET last_activity_at = $2, idle_expires_at = $3
		WHERE token_hmac = $1
	`, tokenHMAC, lastActivity, newIdleExpires)
	return err
}

func (s *Store) DeleteSessionByHMAC(ctx context.Context, tokenHMAC []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hmac = $1`, tokenHMAC)
	return err
}

func (s *Store) DeleteSessionsByUserSub(ctx context.Context, userSub string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_sub = $1`, userSub)
	return err
}

// --- Catalog & Status Queries ---

func (s *Store) ListCatalogWithStatus(ctx context.Context) ([]catalog.Item, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.display_name, c.description, c.category, c.icon_key,
		       c.launch_url, c.protection_mode, c.allowed_roles, COALESCE(c.probe_target_id, ''),
		       c.maintenance_mode, c.maintenance_note,
		       COALESCE(st.state, 'unknown'), COALESCE(st.latency_ms, 0), COALESCE(st.checked_at, TIMESTAMPTZ 'epoch')
		FROM catalog_services c
		LEFT JOIN service_status st ON c.probe_target_id = st.probe_target_id
		ORDER BY c.category ASC, c.display_name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []catalog.Item
	for rows.Next() {
		var it catalog.Item
		if err := rows.Scan(
			&it.ID, &it.DisplayName, &it.Description, &it.Category, &it.IconKey,
			&it.LaunchURL, &it.ProtectionMode, &it.AllowedRoles, &it.ProbeTargetID,
			&it.MaintenanceMode, &it.MaintenanceNote,
			&it.StatusState, &it.LatencyMS, &it.CheckedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

func (s *Store) UpsertCatalogItem(ctx context.Context, it catalog.Item, actor string) error {
	var probeID *string
	if it.ProbeTargetID != "" {
		probeID = &it.ProbeTargetID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO catalog_services (
			id, display_name, description, category, icon_key, launch_url,
			protection_mode, allowed_roles, probe_target_id, maintenance_mode,
			maintenance_note, updated_by, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (id) DO UPDATE SET
			display_name     = EXCLUDED.display_name,
			description      = EXCLUDED.description,
			category         = EXCLUDED.category,
			icon_key         = EXCLUDED.icon_key,
			launch_url       = EXCLUDED.launch_url,
			protection_mode  = EXCLUDED.protection_mode,
			allowed_roles    = EXCLUDED.allowed_roles,
			probe_target_id  = EXCLUDED.probe_target_id,
			maintenance_mode = EXCLUDED.maintenance_mode,
			maintenance_note = EXCLUDED.maintenance_note,
			updated_by       = EXCLUDED.updated_by,
			updated_at       = NOW()
	`,
		it.ID, it.DisplayName, it.Description, it.Category, it.IconKey, it.LaunchURL,
		it.ProtectionMode, it.AllowedRoles, probeID, it.MaintenanceMode,
		it.MaintenanceNote, actor,
	)
	return err
}

func (s *Store) DeleteCatalogItem(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM catalog_services WHERE id = $1`, id)
	return err
}

// UpsertProbeResult is executed by the restricted portal_prober DB role.
func (s *Store) UpsertProbeResult(ctx context.Context, res prober.Result) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO service_status (probe_target_id, state, latency_ms, reason_code, checked_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (probe_target_id) DO UPDATE SET
			state       = EXCLUDED.state,
			latency_ms  = EXCLUDED.latency_ms,
			reason_code = EXCLUDED.reason_code,
			checked_at  = EXCLUDED.checked_at
	`, res.TargetID, res.State, res.LatencyMS, res.ReasonCode, res.CheckedAt)
	return err
}

// --- Audit Logging ---

func (s *Store) RecordAuditEvent(ctx context.Context, ev audit.Event) error {
	metaJSON, err := json.Marshal(ev.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_logs (
			occurred_at, event_type, actor_sub, actor_username, actor_role,
			access_identity, client_ip, target_resource, outcome, metadata_json
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`,
		ev.Timestamp, ev.EventType, ev.ActorSub, ev.ActorUsername, ev.ActorRole,
		ev.AccessIdentity, ev.ClientIP, ev.TargetResource, ev.Outcome, metaJSON,
	)
	return err
}

func (s *Store) ListRecentAuditEvents(ctx context.Context, limit int) ([]audit.Event, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT occurred_at, event_type, actor_sub, actor_username, actor_role,
		       access_identity, client_ip, target_resource, outcome
		FROM audit_logs
		ORDER BY occurred_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []audit.Event
	for rows.Next() {
		var ev audit.Event
		if err := rows.Scan(
			&ev.Timestamp, &ev.EventType, &ev.ActorSub, &ev.ActorUsername, &ev.ActorRole,
			&ev.AccessIdentity, &ev.ClientIP, &ev.TargetResource, &ev.Outcome,
		); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
