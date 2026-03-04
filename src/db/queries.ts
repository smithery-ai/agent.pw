import { eq, and, sql } from 'drizzle-orm'
import { users, services, credentials, revocations, docPages } from './schema'
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

export async function countDistinctOrgs(db: Database) {
  const rows = await db
    .select({ count: sql<number>`count(distinct ${credentials.orgId})::int` })
    .from(credentials)

  return Number(rows[0].count)
}

export async function countCredentialsForService(db: Database, service: string) {
  const rows = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(credentials)
    .where(eq(credentials.service, service))

  return Number(rows[0].count)
}

export async function upsertService(
  db: Database,
  service: string,
  data: {
    baseUrl: string
    authMethod?: string
    headerName?: string
    headerScheme?: string
    displayName?: string
    description?: string
    oauthClientId?: string
    oauthClientSecret?: string
    oauthAuthorizeUrl?: string
    oauthTokenUrl?: string
    oauthScopes?: string
    supportedAuthMethods?: string
    apiType?: string
    docsUrl?: string
    preview?: string
    authConfig?: string
  },
) {
  await db
    .insert(services)
    .values({
      service,
      baseUrl: data.baseUrl,
      authMethod: data.authMethod ?? 'bearer',
      headerName: data.headerName ?? 'Authorization',
      headerScheme: data.headerScheme ?? 'Bearer',
      displayName: data.displayName,
      description: data.description,
      oauthClientId: data.oauthClientId,
      oauthClientSecret: data.oauthClientSecret,
      oauthAuthorizeUrl: data.oauthAuthorizeUrl,
      oauthTokenUrl: data.oauthTokenUrl,
      oauthScopes: data.oauthScopes,
      supportedAuthMethods: data.supportedAuthMethods,
      apiType: data.apiType,
      docsUrl: data.docsUrl,
      preview: data.preview,
      authConfig: data.authConfig,
    })
    .onConflictDoUpdate({
      target: services.service,
      set: {
        baseUrl: sql`excluded.base_url`,
        authMethod: sql`coalesce(excluded.auth_method, ${services.authMethod})`,
        headerName: sql`coalesce(excluded.header_name, ${services.headerName})`,
        headerScheme: sql`coalesce(excluded.header_scheme, ${services.headerScheme})`,
        displayName: sql`coalesce(excluded.display_name, ${services.displayName})`,
        description: sql`coalesce(excluded.description, ${services.description})`,
        oauthClientId: sql`coalesce(excluded.oauth_client_id, ${services.oauthClientId})`,
        oauthClientSecret: sql`coalesce(excluded.oauth_client_secret, ${services.oauthClientSecret})`,
        oauthAuthorizeUrl: sql`coalesce(excluded.oauth_authorize_url, ${services.oauthAuthorizeUrl})`,
        oauthTokenUrl: sql`coalesce(excluded.oauth_token_url, ${services.oauthTokenUrl})`,
        oauthScopes: sql`coalesce(excluded.oauth_scopes, ${services.oauthScopes})`,
        supportedAuthMethods: sql`coalesce(excluded.supported_auth_methods, ${services.supportedAuthMethods})`,
        apiType: sql`coalesce(excluded.api_type, ${services.apiType})`,
        docsUrl: sql`coalesce(excluded.docs_url, ${services.docsUrl})`,
        preview: sql`coalesce(excluded.preview, ${services.preview})`,
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

export async function listCredentialsForService(db: Database, orgId: string, service: string) {
  return db
    .select()
    .from(credentials)
    .where(and(eq(credentials.orgId, orgId), eq(credentials.service, service)))
}

export async function upsertCredential(
  db: Database,
  orgId: string,
  service: string,
  slug: string,
  encryptedCredentials: Buffer,
  tags?: Record<string, string>,
) {
  await db
    .insert(credentials)
    .values({
      orgId,
      service,
      slug,
      encryptedCredentials,
      tags: tags ?? null,
    })
    .onConflictDoUpdate({
      target: [credentials.orgId, credentials.service, credentials.slug],
      set: {
        encryptedCredentials: sql`excluded.encrypted_credentials`,
        tags: sql`coalesce(excluded.tags, ${credentials.tags})`,
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

// ─── Doc Pages ──────────────────────────────────────────────────────────────

export async function getDocPage(db: Database, hostname: string, path: string) {
  const rows = await db
    .select()
    .from(docPages)
    .where(and(eq(docPages.hostname, hostname), eq(docPages.path, path)))
  return rows[0] ?? null
}

export async function upsertDocPage(
  db: Database,
  hostname: string,
  path: string,
  content: string,
  status: string,
  ttlDays?: number,
) {
  await db
    .insert(docPages)
    .values({ hostname, path, content, status, ttlDays: ttlDays ?? 7 })
    .onConflictDoUpdate({
      target: [docPages.hostname, docPages.path],
      set: {
        content: sql`excluded.content`,
        status: sql`excluded.status`,
        generatedAt: sql`now()`,
        ttlDays: sql`coalesce(excluded.ttl_days, ${docPages.ttlDays})`,
      },
    })
}

export async function listDocPages(db: Database, hostname: string) {
  return db.select().from(docPages).where(eq(docPages.hostname, hostname))
}

export async function listSkeletonPages(db: Database, hostname: string) {
  return db
    .select()
    .from(docPages)
    .where(and(eq(docPages.hostname, hostname), eq(docPages.status, 'skeleton')))
}

export async function listStaleDocPages(db: Database, hostname: string) {
  return db
    .select()
    .from(docPages)
    .where(
      and(
        eq(docPages.hostname, hostname),
        sql`${docPages.generatedAt} + (${docPages.ttlDays} || ' days')::interval < now()`,
      ),
    )
}

export async function deleteDocPages(db: Database, hostname: string) {
  return db.delete(docPages).where(eq(docPages.hostname, hostname))
}
