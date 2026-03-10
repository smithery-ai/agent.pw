import { and, eq, sql } from 'drizzle-orm'
import { credProfiles, credentials, revocations, authFlows } from './schema'
import type { Database } from './index'
import {
  credentialParentPath,
  isAncestorOrEqual,
  pathDepth,
} from '../paths'

interface LegacyServiceRecord {
  slug: string
  allowedHosts: string
  authSchemes: string | null
  displayName: string | null
  description: string | null
  oauthClientId: string | null
  encryptedOauthClientSecret: Buffer | null
  docsUrl: string | null
  authConfig: string | null
  createdAt: Date
  updatedAt: Date
}

function parseJsonArray(value: unknown): unknown[] | null {
  return Array.isArray(value) ? value : null
}

function decodeClientSecret(value: unknown): Buffer | null {
  if (typeof value !== 'string' || value.length === 0) return null
  return Buffer.from(value, 'base64')
}

function toLegacyServiceRecord(profile: typeof credProfiles.$inferSelect): LegacyServiceRecord {
  const auth = profile.auth ?? null
  const managedOauth = profile.managedOauth ?? null
  const authSchemes = parseJsonArray(auth?.authSchemes)
  const authConfig = auth?.authConfig

  return {
    slug: profile.slug,
    allowedHosts: JSON.stringify(profile.host),
    authSchemes: authSchemes ? JSON.stringify(authSchemes) : null,
    displayName: profile.displayName,
    description: profile.description,
    oauthClientId:
      typeof managedOauth?.clientId === 'string' ? managedOauth.clientId : null,
    encryptedOauthClientSecret: decodeClientSecret(
      managedOauth?.encryptedClientSecret,
    ),
    docsUrl: typeof auth?.docsUrl === 'string' ? auth.docsUrl : null,
    authConfig: authConfig ? JSON.stringify(authConfig) : null,
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
  }
}

// ─── Cred Profiles ──────────────────────────────────────────────────────────

export async function getCredProfile(db: Database, slug: string) {
  const rows = await db.select().from(credProfiles).where(eq(credProfiles.slug, slug))
  return rows[0] ?? null
}

export async function getCredProfileByHost(db: Database, host: string) {
  const profiles = await listCredProfiles(db)
  return profiles.find(profile => profile.host.includes(host)) ?? null
}

/**
 * Find the best profile for a host at the given token path.
 * Walks up the tree: picks the nearest ancestor profile.
 */
export async function getCredProfileByHostForPath(db: Database, host: string, tokenPath: string) {
  const profiles = await listCredProfiles(db)
  const matching = profiles.filter(p => p.host.includes(host))
  // Find the deepest ancestor of tokenPath among matching profiles
  let best: (typeof matching)[number] | null = null
  for (const p of matching) {
    if (!isAncestorOrEqual(p.path, tokenPath)) continue
    if (!best || pathDepth(p.path) > pathDepth(best.path)) best = p
  }
  return best
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
    const credentialCount = profile.host.reduce((sum, h) => sum + (countMap.get(h) ?? 0), 0)
    return { ...profile, credentialCount }
  })
}

export async function upsertCredProfile(
  db: Database,
  slug: string,
  data: {
    host: string[]
    path?: string
    auth?: Record<string, unknown>
    managedOauth?: Record<string, unknown>
    displayName?: string
    description?: string
  },
) {
  await db
    .insert(credProfiles)
    .values({
      slug,
      host: data.host,
      path: data.path ?? '/',
      auth: data.auth,
      managedOauth: data.managedOauth,
      displayName: data.displayName,
      description: data.description,
    })
    .onConflictDoUpdate({
      target: credProfiles.slug,
      set: {
        host: sql`excluded.host`,
        path: sql`excluded.path`,
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

// ─── Legacy Services Compatibility ──────────────────────────────────────────

// Keep the legacy service API compiling on merged PR builds while the product
// migrates from /services to /cred_profiles.
export async function getService(db: Database, slug: string) {
  const profile = await getCredProfile(db, slug)
  return profile ? toLegacyServiceRecord(profile) : null
}

export async function listServices(db: Database) {
  const profiles = await listCredProfiles(db)
  return profiles.map(toLegacyServiceRecord)
}

export async function listServicesWithCredentialCounts(db: Database) {
  const profiles = await listCredProfilesWithCredentialCounts(db)
  return profiles.map(profile => ({
    ...toLegacyServiceRecord(profile),
    credentialCount: profile.credentialCount,
  }))
}

export async function upsertService(
  db: Database,
  slug: string,
  data: {
    allowedHosts: string[]
    authSchemes?: unknown
    displayName?: string
    description?: string
    oauthClientId?: string
    encryptedOauthClientSecret?: Buffer | null
    docsUrl?: string
    authConfig?: unknown
  },
) {
  const auth: Record<string, unknown> = {}
  if (data.authSchemes !== undefined) auth.authSchemes = data.authSchemes
  if (data.authConfig !== undefined) auth.authConfig = data.authConfig
  if (data.docsUrl !== undefined) auth.docsUrl = data.docsUrl

  const managedOauth: Record<string, unknown> = {}
  if (data.oauthClientId !== undefined) managedOauth.clientId = data.oauthClientId
  if (data.encryptedOauthClientSecret) {
    managedOauth.encryptedClientSecret = data.encryptedOauthClientSecret.toString('base64')
  }

  await upsertCredProfile(db, slug, {
    host: data.allowedHosts,
    auth: Object.keys(auth).length > 0 ? auth : undefined,
    managedOauth:
      Object.keys(managedOauth).length > 0 ? managedOauth : undefined,
    displayName: data.displayName,
    description: data.description,
  })
}

export async function deleteService(db: Database, slug: string) {
  return deleteCredProfile(db, slug)
}

// ─── Credentials ─────────────────────────────────────────────────────────────

export async function getCredential(db: Database, host: string, path: string) {
  const rows = await db
    .select()
    .from(credentials)
    .where(and(eq(credentials.host, host), eq(credentials.path, path)))
  return rows[0] ?? null
}

export async function getCredentialsByHost(db: Database, host: string) {
  return db.select().from(credentials).where(eq(credentials.host, host))
}

export async function listCredentials(db: Database) {
  return db.select().from(credentials)
}

/**
 * List credentials the token can manage (admin flows downward).
 * Returns credentials at the token's path or deeper.
 */
export async function listCredentialsAdminAccessible(
  db: Database,
  tokenPath: string,
) {
  const all = await listCredentials(db)
  return all.filter(credential =>
    isAncestorOrEqual(tokenPath, credentialParentPath(credential.path)),
  )
}


/**
 * List all credentials the token can see: admin-accessible (at path or deeper)
 * plus usage-accessible (at ancestor paths).
 */
export async function listCredentialsAccessible(
  db: Database,
  tokenPath: string,
) {
  const all = await listCredentials(db)
  return all.filter(credential => {
    const parentPath = credentialParentPath(credential.path)
    return isAncestorOrEqual(parentPath, tokenPath) || isAncestorOrEqual(tokenPath, parentPath)
  })
}

/**
 * Find credentials for a host that the token can use (usage flows upward).
 * Returns credentials where credential.path is an ancestor of tokenPath,
 * ordered by path depth descending (deepest ancestor first).
 */
export async function getCredentialsByHostForUsage(
  db: Database,
  host: string,
  tokenPath: string,
) {
  const candidates = await getCredentialsByHost(db, host)
  return candidates
    .filter(credential => isAncestorOrEqual(credentialParentPath(credential.path), tokenPath))
    .sort((a, b) => pathDepth(b.path) - pathDepth(a.path))
}

export async function upsertCredential(
  db: Database,
  data: {
    host: string
    path: string
    auth: Record<string, unknown>
    secret: Buffer
  },
) {
  await db
    .insert(credentials)
    .values({
      host: data.host,
      path: data.path,
      auth: data.auth,
      secret: data.secret,
    })
    .onConflictDoUpdate({
      target: [credentials.host, credentials.path],
      set: {
        auth: sql`excluded.auth`,
        secret: sql`excluded.secret`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteCredential(db: Database, host: string, path: string) {
  const result = await db
    .delete(credentials)
    .where(and(eq(credentials.host, host), eq(credentials.path, path)))
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
  slug: string
  method: 'oauth' | 'api_key'
  codeVerifier?: string
  scopePath?: string
  expiresAt: Date
}

export interface CompleteFlowData {
  token: string
  identity: string
  credentialPath?: string
}

export async function createAuthFlow(db: Database, data: CreateFlowData) {
  await db.insert(authFlows).values({
    id: data.id,
    slug: data.slug,
    method: data.method,
    codeVerifier: data.codeVerifier,
    scopePath: data.scopePath,
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
      credentialPath: data.credentialPath,
    })
    .where(eq(authFlows.id, id))
}
