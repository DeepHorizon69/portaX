#!/usr/bin/env sh
# ==============================================================================
# portaX Portal DB — Least-Privilege Role Separation (executed on first init)
# ==============================================================================
# Roles created:
#   1. portal_migrator: owns schema tables; runs migrations on startup only.
#   2. portal_app:      SELECT/INSERT/UPDATE/DELETE on sessions, catalog, audit.
#                       NO DDL (CREATE/DROP/ALTER), NO REPLICATION, NO SUPERUSER.
#   3. portal_prober:   SELECT/INSERT/UPDATE on service_status ONLY.
#                       Cannot read sessions, catalog secrets, or audit_logs.
# ==============================================================================
set -eu

MIGRATOR_PASS="$(cat /run/secrets/portal_db_migrator_password)"
APP_PASS="$(cat /run/secrets/portal_db_app_password)"
PROBER_PASS="$(cat /run/secrets/portal_db_prober_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  REVOKE CREATE ON SCHEMA public FROM PUBLIC;

  CREATE ROLE portal_migrator WITH LOGIN PASSWORD '${MIGRATOR_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  CREATE ROLE portal_app      WITH LOGIN PASSWORD '${APP_PASS}'      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  CREATE ROLE portal_prober   WITH LOGIN PASSWORD '${PROBER_PASS}'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

  GRANT USAGE, CREATE ON SCHEMA public TO portal_migrator;
  GRANT USAGE ON SCHEMA public TO portal_app, portal_prober;
EOSQL
