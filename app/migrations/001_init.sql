-- ==============================================================================
-- portaX Portal Schema & Least-Privilege Role Grants (001_init.sql)
-- Executed at startup by portal_migrator ONLY.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    token_hmac        BYTEA PRIMARY KEY,
    user_sub          TEXT NOT NULL,
    username          TEXT NOT NULL,
    role              TEXT NOT NULL CHECK (role IN ('viewer', 'admin')),
    access_sub        TEXT NOT NULL,
    csrf_token        TEXT NOT NULL,
    client_ip         TEXT NOT NULL,
    user_agent        TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    idle_expires_at   TIMESTAMPTZ NOT NULL,
    abs_expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_sub ON sessions (user_sub);
CREATE INDEX IF NOT EXISTS idx_sessions_abs_expires ON sessions (abs_expires_at);

CREATE TABLE IF NOT EXISTS catalog_services (
    id                TEXT PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    display_name      TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
    description       TEXT NOT NULL CHECK (char_length(description) BETWEEN 1 AND 280),
    category          TEXT NOT NULL CHECK (char_length(category) BETWEEN 1 AND 40),
    icon_key          TEXT NOT NULL CHECK (icon_key IN ('shield', 'server', 'database', 'network', 'cloud', 'terminal', 'lock', 'activity', 'globe', 'cpu')),
    launch_url        TEXT NOT NULL CHECK (char_length(launch_url) BETWEEN 8 AND 512),
    protection_mode   TEXT NOT NULL CHECK (protection_mode IN ('cloudflare_access', 'authentik_forward_auth', 'tailscale_only')),
    allowed_roles     TEXT[] NOT NULL DEFAULT ARRAY['admin']::TEXT[],
    probe_target_id   TEXT NULL,
    maintenance_mode  BOOLEAN NOT NULL DEFAULT FALSE,
    maintenance_note  TEXT NOT NULL DEFAULT '',
    updated_by        TEXT NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_status (
    probe_target_id   TEXT PRIMARY KEY,
    state             TEXT NOT NULL CHECK (state IN ('up', 'down', 'degraded', 'unknown')),
    latency_ms        INTEGER NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
    reason_code       TEXT NOT NULL CHECK (reason_code IN ('ok', 'timeout', 'tls_error', 'unexpected_status', 'unreachable', 'ssrf_blocked')),
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id                BIGSERIAL PRIMARY KEY,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type        TEXT NOT NULL,
    actor_sub         TEXT NOT NULL,
    actor_username    TEXT NOT NULL,
    actor_role        TEXT NOT NULL,
    access_identity   TEXT NOT NULL,
    client_ip         TEXT NOT NULL,
    target_resource   TEXT NOT NULL,
    outcome           TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    metadata_json     JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON audit_logs (occurred_at DESC);

-- ==============================================================================
-- Enforce Least-Privilege Table Grants
--   1. portal_app:    CRUD on sessions, catalog_services; SELECT on service_status;
--                     INSERT & SELECT on audit_logs (cannot DELETE/UPDATE audit logs!).
--   2. portal_prober: SELECT/INSERT/UPDATE on service_status ONLY.
-- ==============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portal_app') THEN
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM portal_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE sessions TO portal_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE catalog_services TO portal_app;
        GRANT SELECT ON TABLE service_status TO portal_app;
        GRANT SELECT, INSERT ON TABLE audit_logs TO portal_app;
        GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO portal_app;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portal_prober') THEN
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM portal_prober;
        GRANT SELECT, INSERT, UPDATE ON TABLE service_status TO portal_prober;
    END IF;
END
$$;
