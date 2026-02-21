import { env } from 'cloudflare:test'

const statements = [
  `CREATE TABLE IF NOT EXISTS services (
    service TEXT NOT NULL,
    base_url TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'bearer',
    header_name TEXT NOT NULL DEFAULT 'Authorization',
    header_scheme TEXT NOT NULL DEFAULT 'Bearer',
    description TEXT,
    spec_url TEXT,
    auth_config TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (service)
  )`,
  `CREATE TABLE IF NOT EXISTS credentials (
    service TEXT NOT NULL,
    identity TEXT NOT NULL DEFAULT 'default',
    token TEXT NOT NULL,
    metadata TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (service, identity)
  )`,
  `CREATE TABLE IF NOT EXISTS revocations (
    revocation_id TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT
  )`,
]

for (const sql of statements) {
  await env.DB.prepare(sql).run()
}
