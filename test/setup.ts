import { drizzle } from 'drizzle-orm/pglite'
import { sql } from 'drizzle-orm'
import * as schema from '../src/db/schema'
import { mintToken } from '../src/biscuit'
import { buildSetCookieHeader, SESSION_TTL_SECONDS } from '../src/managed/session'

export const BISCUIT_PRIVATE_KEY =
  'ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad'

export const TEST_SESSION_SECRET = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64')
export const TEST_ORG_ID = 'org_test_456'

export async function buildTestSessionCookie(userId = 'user_test_123', orgId = TEST_ORG_ID, email = 'test@example.com') {
  const header = await buildSetCookieHeader(TEST_SESSION_SECRET, {
    workosUserId: userId,
    orgId,
    email,
    name: 'Test User',
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  })
  // Extract just the cookie value (name=value part) from the Set-Cookie header
  return header.split(';')[0]
}

export function mintRootToken() {
  return mintToken(
    BISCUIT_PRIVATE_KEY,
    'local',
    ['admin', 'manage_services'],
  )
}

export async function createTestDb() {
  const db = drizzle({ connection: { dataDir: 'memory://' }, schema })

  // Create the warden schema and tables
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
      slug TEXT PRIMARY KEY,
      allowed_hosts TEXT NOT NULL,
      display_name TEXT,
      description TEXT,
      auth_schemes TEXT,
      oauth_client_id TEXT,
      encrypted_oauth_client_secret BYTEA,
      docs_url TEXT,
      auth_config TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS warden.credentials (
      org_id TEXT NOT NULL,
      slug TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT 'default',
      encrypted_credentials BYTEA NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      PRIMARY KEY (org_id, slug, label)
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
      slug TEXT NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code_verifier TEXT,
      org_id TEXT,
      token TEXT,
      identity TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  return db
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>
