import { drizzle } from 'drizzle-orm/pglite'
import { sql } from 'drizzle-orm'
import * as schema from '../src/db/schema'
import { mintManagementToken, mintToken } from '../src/biscuit'

export const BISCUIT_PRIVATE_KEY =
  'ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad'

export function mintRootToken() {
  return mintManagementToken(
    BISCUIT_PRIVATE_KEY,
    ['manage_services', 'manage_vaults'],
    ['*'],
  )
}

export function mintProxyToken(services: string, vault: string) {
  return mintToken(BISCUIT_PRIVATE_KEY, [
    { services, vault, metadata: { userId: 'alice' } },
  ])
}

export async function createTestDb() {
  const db = drizzle({ connection: { dataDir: 'memory://' }, schema })

  // Create the warden schema and tables
  await db.execute(sql`CREATE SCHEMA IF NOT EXISTS warden`)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.vaults (
      slug TEXT PRIMARY KEY,
      display_name TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.services (
      service TEXT PRIMARY KEY,
      base_url TEXT NOT NULL,
      display_name TEXT,
      description TEXT,
      auth_method TEXT NOT NULL DEFAULT 'bearer',
      header_name TEXT NOT NULL DEFAULT 'Authorization',
      header_scheme TEXT NOT NULL DEFAULT 'Bearer',
      oauth_client_id TEXT,
      oauth_client_secret TEXT,
      oauth_authorize_url TEXT,
      oauth_token_url TEXT,
      oauth_scopes TEXT,
      supported_auth_methods TEXT,
      api_type TEXT,
      docs_url TEXT,
      preview TEXT,
      auth_config TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.credentials (
      vault_slug TEXT NOT NULL,
      service TEXT NOT NULL,
      identity TEXT,
      encrypted_credentials BYTEA NOT NULL,
      metadata TEXT,
      expires_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (vault_slug, service)
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
    CREATE TABLE IF NOT EXISTS warden.auth_flows (
      id TEXT PRIMARY KEY,
      service TEXT NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code_verifier TEXT,
      vault_slug TEXT,
      warden_token TEXT,
      identity TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      expires_at TIMESTAMP NOT NULL
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.doc_pages (
      hostname TEXT NOT NULL,
      path TEXT NOT NULL,
      content TEXT,
      status TEXT NOT NULL DEFAULT 'skeleton',
      generated_at TIMESTAMP NOT NULL DEFAULT now(),
      ttl_days INT NOT NULL DEFAULT 7,
      PRIMARY KEY (hostname, path)
    )
  `)

  return db
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>
