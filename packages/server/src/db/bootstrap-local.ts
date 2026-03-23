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
      path TEXT NOT NULL,
      profile_path TEXT,
      host TEXT,
      auth JSONB NOT NULL,
      secret BYTEA NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (path)
    )
  `)

  await db.execute(sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'agentpw'
          AND table_name = 'credentials'
          AND column_name = 'profile_path'
      ) THEN
        ALTER TABLE agentpw.credentials ADD COLUMN profile_path TEXT;
      END IF;
    END $$;
  `)

  await db.execute(sql`
    UPDATE agentpw.credentials
    SET profile_path = path
    WHERE profile_path IS NULL
  `)

  await db.execute(sql`
    ALTER TABLE agentpw.credentials
    ALTER COLUMN profile_path SET NOT NULL
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS credentials_host_idx
    ON agentpw.credentials (host)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS credentials_profile_path_idx
    ON agentpw.credentials (profile_path)
  `)

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS credentials_profile_path_path_idx
    ON agentpw.credentials (profile_path, path)
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_flows
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.verification
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_accounts
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_sessions
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_users
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.auth_verifications
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.issued_tokens
  `)

  await db.execute(sql`
    DROP TABLE IF EXISTS agentpw.revocations
  `)
}
