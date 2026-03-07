import { drizzle } from 'drizzle-orm/pglite'
import { sql } from 'drizzle-orm'
import * as schema from '@agent.pw/server/db/schema'

export const BISCUIT_PRIVATE_KEY =
  'ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad'

export const TEST_ORG_ID = 'org_test_456'
export const PUBLIC_KEY_HEX =
  'ed25519/e43c506c0d441f5b4e4ccac8c7572ac5b9d3773a3a95c21584164bec11f0d9ab'
export const ROOT_TOKEN =
  'apw_Et8BCnUKBWxvY2FsCgthcHdfdXNlcl9pZAoJYXB3X3JpZ2h0Cg9tYW5hZ2Vfc2VydmljZXMYAyIJCgcIChIDGIAIIgoKCAiBCBIDGIAIIggKBggEEgIYDSIJCgcIgggSAhgNIgkKBwgEEgMYgwgiCgoICIIIEgMYgwgSJAgAEiDbNEU90WEHi3F50uL58WqtjG44f5PyGx4DqWADYZFo2RpAULFl2PrOfpFbnYTf34vjWGZTZZvtVrvIkXOkJqjFxbvgMQNXwFpEieQ0VUd0CVdyyhY0X2ZJx06hyfAAz-m0ACIiCiCpSp7XIW3EzHRDIBvL4F3H4FpsPtUQDA5qqAsUXXRQBA=='
export const ORG_TOKEN =
  'apw_EsEBClcKDXVzZXJfdGVzdF8xMjMKC2Fwd191c2VyX2lkCgZvcmdfaWQKDG9yZ190ZXN0XzQ1NhgDIgkKBwgKEgMYgAgiCgoICIEIEgMYgAgiCgoICIIIEgMYgwgSJAgAEiB9mmA7aHk9nraGp-kNgDvEr3lMqRlV5L4XM-sVud5hExpACC78EUybNmLT7DXkRC8EUMrTm13As19X87Bb0OESx6rkL04ZmzTioCS1zPjsC1T116UNEjz9XFZIS0sBjinhAiIiCiChD_vSIHjWv5vqa4zXCSo_N9zrbpxreBc0U6sY4CMwkA=='

export async function createTestDb() {
  const db = drizzle({ connection: { dataDir: 'memory://' }, schema })

  await db.execute(sql`CREATE SCHEMA IF NOT EXISTS agentpw`)

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS agentpw.cred_profiles (
      slug TEXT PRIMARY KEY,
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
      id TEXT PRIMARY KEY,
      host TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      auth JSONB NOT NULL,
      secret BYTEA NOT NULL,
      exec_policy TEXT,
      admin_policy TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
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
      slug TEXT NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      code_verifier TEXT,
      exec_policy TEXT,
      token TEXT,
      identity TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `)

  return db
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>
