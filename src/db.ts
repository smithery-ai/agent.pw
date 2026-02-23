import type { ServiceRow, CredentialRow } from './types'

export async function getService(
  db: D1Database,
  service: string
): Promise<ServiceRow | null> {
  return db
    .prepare('SELECT * FROM services WHERE service = ?')
    .bind(service)
    .first<ServiceRow>()
}

export async function listServices(db: D1Database): Promise<ServiceRow[]> {
  const result = await db
    .prepare('SELECT * FROM services')
    .all<ServiceRow>()
  return result.results
}

export async function upsertService(
  db: D1Database,
  service: string,
  data: {
    base_url: string
    auth_method?: string
    header_name?: string
    header_scheme?: string
    description?: string
    spec_url?: string
    auth_config?: string
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO services (service, base_url, auth_method, header_name, header_scheme, description, spec_url, auth_config, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT (service) DO UPDATE SET
         base_url = excluded.base_url,
         auth_method = COALESCE(excluded.auth_method, services.auth_method),
         header_name = COALESCE(excluded.header_name, services.header_name),
         header_scheme = COALESCE(excluded.header_scheme, services.header_scheme),
         description = COALESCE(excluded.description, services.description),
         spec_url = COALESCE(excluded.spec_url, services.spec_url),
         auth_config = COALESCE(excluded.auth_config, services.auth_config),
         updated_at = datetime('now')`
    )
    .bind(
      service,
      data.base_url,
      data.auth_method ?? 'bearer',
      data.header_name ?? 'Authorization',
      data.header_scheme ?? 'Bearer',
      data.description ?? null,
      data.spec_url ?? null,
      data.auth_config ?? null
    )
    .run()
}

export async function deleteService(
  db: D1Database,
  service: string
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM services WHERE service = ?')
    .bind(service)
    .run()
  return result.meta.changes > 0
}

export async function getCredential(
  db: D1Database,
  service: string,
  identity: string
): Promise<CredentialRow | null> {
  return db
    .prepare('SELECT * FROM credentials WHERE service = ? AND identity = ?')
    .bind(service, identity)
    .first<CredentialRow>()
}

export async function upsertCredential(
  db: D1Database,
  service: string,
  identity: string,
  token: string,
  metadata?: Record<string, string>,
  expiresAt?: string
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO credentials (service, identity, token, metadata, expires_at, updated_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT (service, identity) DO UPDATE SET
         token = excluded.token,
         metadata = COALESCE(excluded.metadata, credentials.metadata),
         expires_at = excluded.expires_at,
         updated_at = datetime('now')`
    )
    .bind(
      service,
      identity,
      token,
      metadata ? JSON.stringify(metadata) : null,
      expiresAt ?? null
    )
    .run()
}

export async function deleteCredential(
  db: D1Database,
  service: string,
  identity: string
): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM credentials WHERE service = ? AND identity = ?')
    .bind(service, identity)
    .run()
  return result.meta.changes > 0
}

export async function findCredentialsByMetadata(
  db: D1Database,
  service: string,
  metadata: Record<string, string>
): Promise<CredentialRow[]> {
  const result = await db
    .prepare('SELECT * FROM credentials WHERE service = ?')
    .bind(service)
    .all<CredentialRow>()

  return result.results.filter(row => {
    if (!row.metadata) return false
    const rowMeta = JSON.parse(row.metadata)
    return Object.entries(metadata).every(([k, v]) => rowMeta[k] === v)
  })
}

export async function isRevoked(db: D1Database, revocationId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 FROM revocations WHERE revocation_id = ?')
    .bind(revocationId)
    .first()
  return row !== null
}

export async function revokeToken(
  db: D1Database,
  revocationId: string,
  reason?: string
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO revocations (revocation_id, reason) VALUES (?, ?) ON CONFLICT DO NOTHING`
    )
    .bind(revocationId, reason ?? null)
    .run()
}
