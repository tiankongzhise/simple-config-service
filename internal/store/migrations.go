package store

import (
	"context"
	"database/sql"
)

const schemaSQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS configs (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	application TEXT NOT NULL,
	environment TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	value_ciphertext TEXT NOT NULL,
	encrypted_data_key TEXT NOT NULL,
	nonce TEXT NOT NULL,
	data_key_nonce TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	key_id TEXT NOT NULL,
	version INTEGER NOT NULL DEFAULT 1,
	status TEXT NOT NULL DEFAULT 'enabled',
	deleted_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS configs_unique_live_key
ON configs (user_id, key, application, environment)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS configs_lookup_idx
ON configs (user_id, application, environment, status)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS config_versions (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	config_id UUID NOT NULL REFERENCES configs(id) ON DELETE CASCADE,
	user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	version INTEGER NOT NULL,
	key TEXT NOT NULL,
	application TEXT NOT NULL,
	environment TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	value_ciphertext TEXT NOT NULL,
	encrypted_data_key TEXT NOT NULL,
	nonce TEXT NOT NULL,
	data_key_nonce TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	key_id TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (config_id, version)
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	user_id UUID REFERENCES users(id) ON DELETE SET NULL,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id UUID,
	metadata JSONB NOT NULL DEFAULT '{}',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_logs_user_created_idx
ON audit_logs (user_id, created_at DESC);
`

func RunMigrations(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, schemaSQL)
	return err
}
