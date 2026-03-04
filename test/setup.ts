import { drizzle } from 'drizzle-orm/pglite'
import { sql } from 'drizzle-orm'
import * as schema from '../src/db/schema'
import { mintManagementToken, mintToken } from '../src/biscuit'
import { buildSetCookieHeader, SESSION_TTL_SECONDS } from '../src/lib/session'

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
  return mintManagementToken(
    BISCUIT_PRIVATE_KEY,
    ['manage_services', 'manage_vaults'],
    ['*'],
  )
}

export function mintProxyToken(services: string, orgId: string) {
  return mintToken(BISCUIT_PRIVATE_KEY, [
    { services, vault: orgId, metadata: { userId: 'alice' } },
  ])
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
    CREATE TABLE IF NOT EXISTS warden.revocations (
      revocation_id TEXT PRIMARY KEY,
      revoked_at TIMESTAMP NOT NULL DEFAULT now(),
      reason TEXT
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

/** Map-backed fake that implements the Redis subset used by auth-flow-store. */
export function createTestRedis() {
  const store = new Map<string, string>()
  return {
    async get(key: string) {
      return store.get(key) ?? null
    },
    async set(key: string, value: string, _opts?: { ex?: number }) {
      store.set(key, value)
    },
  } as import('@upstash/redis').Redis
}
