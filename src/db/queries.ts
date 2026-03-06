import { eq, sql } from 'drizzle-orm'
import { credProfiles, credentials, revocations, authFlows } from './schema'
import type { Database } from './index'

// ─── Cred Profiles ──────────────────────────────────────────────────────────

export async function getCredProfile(db: Database, slug: string) {
  const rows = await db.select().from(credProfiles).where(eq(credProfiles.slug, slug))
  return rows[0] ?? null
}

export async function listCredProfiles(db: Database) {
  return db.select().from(credProfiles)
}

export async function listCredProfilesWithCredentialCounts(db: Database) {
  const [allProfiles, counts] = await Promise.all([
    listCredProfiles(db),
    db
      .select({
        host: credentials.host,
        count: sql<number>`count(*)::int`,
      })
      .from(credentials)
      .groupBy(credentials.host),
  ])

  const countMap = new Map<string, number>()
  for (const row of counts) {
    countMap.set(row.host, Number(row.count))
  }

  return allProfiles.map(profile => {
    const hosts: string[] = JSON.parse(profile.host)
    const credentialCount = hosts.reduce((sum, h) => sum + (countMap.get(h) ?? 0), 0)
    return { ...profile, credentialCount }
  })
}

export async function upsertCredProfile(
  db: Database,
  slug: string,
  data: {
    host: string
    auth?: string
    managedOauth?: string
    displayName?: string
    description?: string
  },
) {
  await db
    .insert(credProfiles)
    .values({
      slug,
      host: data.host,
      auth: data.auth,
      managedOauth: data.managedOauth,
      displayName: data.displayName,
      description: data.description,
    })
    .onConflictDoUpdate({
      target: credProfiles.slug,
      set: {
        host: sql`excluded.host`,
        auth: sql`coalesce(excluded.auth, ${credProfiles.auth})`,
        managedOauth: sql`coalesce(excluded.managed_oauth, ${credProfiles.managedOauth})`,
        displayName: sql`coalesce(excluded.display_name, ${credProfiles.displayName})`,
        description: sql`coalesce(excluded.description, ${credProfiles.description})`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteCredProfile(db: Database, slug: string) {
  const result = await db.delete(credProfiles).where(eq(credProfiles.slug, slug)).returning()
  return result.length > 0
}

// ─── Credentials ─────────────────────────────────────────────────────────────

export async function getCredentialById(db: Database, id: string) {
  const rows = await db.select().from(credentials).where(eq(credentials.id, id))
  return rows[0] ?? null
}

export async function getCredentialBySlug(db: Database, slug: string) {
  const rows = await db.select().from(credentials).where(eq(credentials.slug, slug))
  return rows[0] ?? null
}

export async function getCredentialsByHost(db: Database, host: string) {
  return db.select().from(credentials).where(eq(credentials.host, host))
}

export async function listCredentials(db: Database) {
  return db.select().from(credentials)
}

export async function upsertCredential(
  db: Database,
  data: {
    id: string
    host: string
    slug: string
    auth: string
    secret: Buffer
    execPolicy?: string
    adminPolicy?: string
  },
) {
  await db
    .insert(credentials)
    .values(data)
    .onConflictDoUpdate({
      target: credentials.id,
      set: {
        host: sql`excluded.host`,
        slug: sql`excluded.slug`,
        auth: sql`excluded.auth`,
        secret: sql`excluded.secret`,
        execPolicy: sql`coalesce(excluded.exec_policy, ${credentials.execPolicy})`,
        adminPolicy: sql`coalesce(excluded.admin_policy, ${credentials.adminPolicy})`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteCredential(db: Database, slug: string) {
  const result = await db.delete(credentials).where(eq(credentials.slug, slug)).returning()
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
  slug: string
  method: string
  codeVerifier?: string
  execPolicy?: string
  expiresAt: Date
}

export interface CompleteFlowData {
  token: string
  identity: string
}

export async function createAuthFlow(db: Database, data: CreateFlowData) {
  await db.insert(authFlows).values({
    id: data.id,
    slug: data.slug,
    method: data.method,
    codeVerifier: data.codeVerifier,
    execPolicy: data.execPolicy,
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
    })
    .where(eq(authFlows.id, id))
}
