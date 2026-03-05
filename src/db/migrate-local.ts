import { sql } from 'drizzle-orm'
import type { Database } from './index'

/** Initialize all tables in a fresh local PGlite database. */
export async function migrateLocal(db: Database) {
  await db.execute(sql`CREATE SCHEMA IF NOT EXISTS warden`)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.users (
      workos_user_id TEXT PRIMARY KEY,
      workos_org_id TEXT NOT NULL,
      email TEXT,
      name TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.services (
      service TEXT PRIMARY KEY,
      base_url TEXT NOT NULL,
      display_name TEXT,
      description TEXT,
      auth_schemes TEXT,
      oauth_client_id TEXT,
      encrypted_oauth_client_secret BYTEA,
      docs_url TEXT,
      auth_config TEXT,
      webhook_config TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.credentials (
      org_id TEXT NOT NULL,
      service TEXT NOT NULL,
      slug TEXT NOT NULL DEFAULT 'default',
      encrypted_credentials BYTEA NOT NULL,
      tags JSONB,
      expires_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (org_id, service, slug)
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.oauth_apps (
      org_id TEXT NOT NULL,
      service TEXT NOT NULL,
      client_id TEXT NOT NULL,
      encrypted_client_secret BYTEA,
      scopes TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (org_id, service)
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.revocations (
      revocation_id TEXT PRIMARY KEY,
      revoked_at TIMESTAMP NOT NULL DEFAULT now(),
      reason TEXT
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.webhook_registrations (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      service TEXT NOT NULL,
      callback_url TEXT NOT NULL,
      encrypted_webhook_secret BYTEA,
      metadata TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.auth_flows (
      id TEXT PRIMARY KEY,
      service TEXT NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code_verifier TEXT,
      org_id TEXT,
      oauth_source TEXT,
      warden_token TEXT,
      identity TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)
}
