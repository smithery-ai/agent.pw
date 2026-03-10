import { drizzle } from 'drizzle-orm/pglite'
import { sql } from 'drizzle-orm'
import * as schema from '@agent.pw/server/db/schema'
import { mintToken } from '@agent.pw/server/biscuit'

export const BISCUIT_PRIVATE_KEY =
  'ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad'

export const TEST_ORG_ID = 'org_test_456'
export const PUBLIC_KEY_HEX =
  'ed25519/e43c506c0d441f5b4e4ccac8c7572ac5b9d3773a3a95c21584164bec11f0d9ab'

function escapeDatalog(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export const ROOT_TOKEN = mintToken(BISCUIT_PRIVATE_KEY, 'local', ['manage_services'])

export const ORG_TOKEN = mintToken(BISCUIT_PRIVATE_KEY, 'user_test_123', undefined, [
  `apw:org_id("${escapeDatalog(TEST_ORG_ID)}")`,
  `apw:path("${escapeDatalog(`/${TEST_ORG_ID}`)}")`,
])

function escapeDatalog(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export function mintTestToken(
  orgId: string,
  rights?: string[],
  path?: string,
) {
  const extraFacts = [`apw_org_id("${escapeDatalog(orgId)}")`]
  if (path) {
    extraFacts.push(`apw_path("${escapeDatalog(path)}")`)
  }
  return mintToken(BISCUIT_PRIVATE_KEY, orgId, rights, extraFacts)
}

export async function createTestDb() {
  const db = drizzle({ connection: { dataDir: 'memory://' }, schema })

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

  return db
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>
