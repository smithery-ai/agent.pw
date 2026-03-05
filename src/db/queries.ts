import { eq, and, sql } from 'drizzle-orm'
import { users, services, credentials, revocations, authFlows } from './schema'
import type { Database } from './index'

// ─── Users ──────────────────────────────────────────────────────────────────

export async function getUser(db: Database, workosUserId: string) {
  const rows = await db.select().from(users).where(eq(users.workosUserId, workosUserId))
  return rows[0] ?? null
}

export async function upsertUser(
  db: Database,
  data: { workosUserId: string; workosOrgId: string; email?: string; name?: string },
) {
  await db
    .insert(users)
    .values(data)
    .onConflictDoUpdate({
      target: users.workosUserId,
      set: {
        workosOrgId: sql`excluded.workos_org_id`,
        email: sql`coalesce(excluded.email, ${users.email})`,
        name: sql`coalesce(excluded.name, ${users.name})`,
      },
    })
}

// ─── Services ────────────────────────────────────────────────────────────────

export async function getService(db: Database, service: string) {
  const rows = await db.select().from(services).where(eq(services.service, service))
  return rows[0] ?? null
}

export async function listServices(db: Database) {
  return db.select().from(services)
}

export async function listServicesWithCredentialCounts(db: Database) {
  const [allServices, counts] = await Promise.all([
    listServices(db),
    db
      .select({
        service: credentials.service,
        count: sql<number>`count(*)::int`,
      })
      .from(credentials)
      .groupBy(credentials.service),
  ])

  const countMap = new Map<string, number>()
  for (const row of counts) {
    countMap.set(row.service, Number(row.count))
  }

  return allServices.map(service => ({
    ...service,
    credentialCount: countMap.get(service.service) ?? 0,
  }))
}

export async function upsertService(
  db: Database,
  service: string,
  data: {
    baseUrl: string
    authSchemes?: string
    displayName?: string
    description?: string
    oauthClientId?: string
    encryptedOauthClientSecret?: Buffer | null
    docsUrl?: string
    authConfig?: string
  },
) {
  await db
    .insert(services)
    .values({
      service,
      baseUrl: data.baseUrl,
      authSchemes: data.authSchemes,
      displayName: data.displayName,
      description: data.description,
      oauthClientId: data.oauthClientId,
      encryptedOauthClientSecret: data.encryptedOauthClientSecret ?? null,
      docsUrl: data.docsUrl,
      authConfig: data.authConfig,
    })
    .onConflictDoUpdate({
      target: services.service,
      set: {
        baseUrl: sql`excluded.base_url`,
        authSchemes: sql`coalesce(excluded.auth_schemes, ${services.authSchemes})`,
        displayName: sql`coalesce(excluded.display_name, ${services.displayName})`,
        description: sql`coalesce(excluded.description, ${services.description})`,
        oauthClientId: sql`coalesce(excluded.oauth_client_id, ${services.oauthClientId})`,
        encryptedOauthClientSecret: sql`coalesce(excluded.encrypted_oauth_client_secret, ${services.encryptedOauthClientSecret})`,
        docsUrl: sql`coalesce(excluded.docs_url, ${services.docsUrl})`,
        authConfig: sql`coalesce(excluded.auth_config, ${services.authConfig})`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteService(db: Database, service: string) {
  const result = await db.delete(services).where(eq(services.service, service)).returning()
  return result.length > 0
}

// ─── Credentials ─────────────────────────────────────────────────────────────

export async function getCredential(db: Database, orgId: string, service: string, slug = 'default') {
  const rows = await db
    .select()
    .from(credentials)
    .where(and(eq(credentials.orgId, orgId), eq(credentials.service, service), eq(credentials.slug, slug)))
  return rows[0] ?? null
}

export async function listCredentials(db: Database, orgId: string) {
  return db.select().from(credentials).where(eq(credentials.orgId, orgId))
}

export async function upsertCredential(
  db: Database,
  orgId: string,
  service: string,
  slug: string,
  encryptedCredentials: Buffer,
) {
  await db
    .insert(credentials)
    .values({
      orgId,
      service,
      slug,
      encryptedCredentials,
    })
    .onConflictDoUpdate({
      target: [credentials.orgId, credentials.service, credentials.slug],
      set: {
        encryptedCredentials: sql`excluded.encrypted_credentials`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteCredential(db: Database, orgId: string, service: string, slug: string) {
  const result = await db
    .delete(credentials)
    .where(and(eq(credentials.orgId, orgId), eq(credentials.service, service), eq(credentials.slug, slug)))
    .returning()
  return result.length > 0
}

// ─── Revocations ─────────────────────────────────────────────────────────────

export async function isRevoked(db: Database, revocationId: string) {
  const rows = await db
    .select()
    .from(revocations)
    .where(eq(revocations.revocationId, revocationId))
  return rows.length > 0
}

export async function revokeToken(db: Database, revocationId: string, reason?: string) {
  await db
    .insert(revocations)
    .values({ revocationId, reason })
    .onConflictDoNothing()
}

// ─── Auth Flows ──────────────────────────────────────────────────────────────

export interface CreateFlowData {
  id: string
  service: string
  method: string
  codeVerifier?: string
  orgId?: string
  expiresAt: Date
}

export interface CompleteFlowData {
  token: string
  identity: string
  orgId: string
}

export async function createAuthFlow(db: Database, data: CreateFlowData) {
  await db.insert(authFlows).values({
    id: data.id,
    service: data.service,
    method: data.method,
    codeVerifier: data.codeVerifier,
    orgId: data.orgId,
    expiresAt: data.expiresAt,
  })
}

export async function getAuthFlow(db: Database, id: string) {
  const rows = await db
    .select()
    .from(authFlows)
    .where(eq(authFlows.id, id))
  const flow = rows[0] ?? null
  if (!flow) return null
  if (flow.expiresAt < new Date()) return null
  return flow
}

export async function completeAuthFlow(db: Database, id: string, data: CompleteFlowData) {
  await db
    .update(authFlows)
    .set({
      status: 'completed',
      token: data.token,
      identity: data.identity,
      orgId: data.orgId,
    })
    .where(eq(authFlows.id, id))
}
