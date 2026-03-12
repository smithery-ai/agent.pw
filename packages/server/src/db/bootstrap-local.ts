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
      managed_oauth JSONB,
      display_name TEXT,
      description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
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
    CREATE TABLE IF NOT EXISTS agentpw.auth_flows (
      id TEXT PRIMARY KEY,
      profile_path TEXT,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code_verifier TEXT,
      scope_path TEXT,
      token TEXT,
      identity TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)
}
