import { sql } from 'drizzle-orm'
import type { Database } from './index'

/** Bootstrap the local PGlite schema without relying on checked-in Drizzle migrations. */
export async function bootstrapLocalSchema(db: Database) {
  await db.execute(sql`CREATE SCHEMA IF NOT EXISTS agentpw`)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.cred_profiles (
      path TEXT PRIMARY KEY,
      host JSONB NOT NULL,
      auth JSONB,
      oauth_config JSONB,
      display_name TEXT,
      description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'agentpw'
          AND table_name = 'cred_profiles'
          AND column_name = 'managed_oauth'
      ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'agentpw'
          AND table_name = 'cred_profiles'
          AND column_name = 'oauth_config'
      ) THEN
        ALTER TABLE agentpw.cred_profiles RENAME COLUMN managed_oauth TO oauth_config;
      END IF;
    END $$;
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS cred_profiles_path_idx
    ON agentpw.cred_profiles (path)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS cred_profiles_host_idx
    ON agentpw.cred_profiles USING gin (host)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.credentials (
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      auth JSONB NOT NULL,
      secret BYTEA NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (host, path)
    )
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS credentials_host_idx
    ON agentpw.credentials (host)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS credentials_host_path_idx
    ON agentpw.credentials (host, path)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.revocations (
      revocation_id TEXT PRIMARY KEY,
      revoked_at TIMESTAMP NOT NULL DEFAULT now(),
      reason TEXT
    )
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_flows
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.verification
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.auth_users (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      email TEXT NOT NULL,
      email_verified BOOLEAN NOT NULL DEFAULT false,
      name TEXT NOT NULL,
      image TEXT
    )
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_users_email_idx
    ON agentpw.auth_users (email)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.auth_sessions (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      user_id TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      token TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT
    )
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_sessions_user_id_idx
    ON agentpw.auth_sessions (user_id)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_sessions_token_idx
    ON agentpw.auth_sessions (token)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.auth_accounts (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      provider_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      access_token TEXT,
      refresh_token TEXT,
      id_token TEXT,
      access_token_expires_at TIMESTAMP,
      refresh_token_expires_at TIMESTAMP,
      scope TEXT,
      password TEXT
    )
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_accounts_user_id_idx
    ON agentpw.auth_accounts (user_id)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_accounts_provider_account_idx
    ON agentpw.auth_accounts (provider_id, account_id)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.auth_verifications (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      value TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      identifier TEXT NOT NULL
    )
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS auth_verifications_identifier_idx
    ON agentpw.auth_verifications (identifier)
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.issued_tokens (
      id TEXT PRIMARY KEY,
      owner_user_id TEXT,
      org_id TEXT,
      name TEXT,
      token_hash TEXT NOT NULL,
      revocation_ids JSONB NOT NULL,
      rights JSONB NOT NULL,
      constraints JSONB NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      expires_at TIMESTAMP,
      last_used_at TIMESTAMP,
      revoked_at TIMESTAMP,
      revoke_reason TEXT
    )
  `)

  await db.execute(sql`
    CREATE UNIQUE INDEX IF NOT EXISTS issued_tokens_token_hash_idx
    ON agentpw.issued_tokens (token_hash)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS issued_tokens_owner_user_created_idx
    ON agentpw.issued_tokens (owner_user_id, created_at)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS issued_tokens_org_created_idx
    ON agentpw.issued_tokens (org_id, created_at)
  `)
}
