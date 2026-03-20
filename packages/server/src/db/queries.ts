import {
  and,
  asc,
  desc,
  eq,
  gt,
  type InferSelectModel,
  isNull,
  like,
  lt,
  or,
  sql,
  type SQL,
} from 'drizzle-orm'
import type { TokenConstraint, TokenRight } from '../core/types.js'
import { credProfiles, credentials, revocations, authFlows, issuedTokens } from './schema/index.js'
import type { Database } from './index.js'
import {
  credentialName,
  credentialParentPath,
  isAncestorOrEqual,
  pathDepth,
} from '../paths.js'

type CredProfileRow = Omit<InferSelectModel<typeof credProfiles>, 'host'> & {
  host: string[]
}

type CredentialRow = InferSelectModel<typeof credentials>

function normalizeHostList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
  }
  if (typeof value === 'string' && value.length > 0) {
    return [value]
  }
  return []
}

function compareByDeepestPath<T extends { path: string }>(a: T, b: T) {
  return pathDepth(b.path) - pathDepth(a.path) || a.path.localeCompare(b.path)
}

export interface QueryPage<T> {
  items: T[]
  hasMore: boolean
}

function takePage<T>(rows: T[], limit: number): QueryPage<T> {
  return {
    items: rows.slice(0, limit),
    hasMore: rows.length > limit,
  }
}

function pathWithinRootCondition(
  column: typeof credProfiles.path | typeof credentials.path,
  root: string,
): SQL<unknown> {
  if (root === '/') {
    return sql`true`
  }
  /* v8 ignore next -- eq+like always provide at least one SQL branch here */
  return or(eq(column, root), like(column, `${root}/%`)) ?? sql`false`
}

function pathWithinAnyRootCondition(
  column: typeof credProfiles.path | typeof credentials.path,
  roots: string[],
): SQL<unknown> {
  /* v8 ignore start -- public callers short-circuit empty roots before building SQL */
  if (roots.length === 0) {
    return sql`false`
  }
  /* v8 ignore stop */
  /* v8 ignore next -- non-empty roots always produce at least one SQL branch here */
  return or(...roots.map(root => pathWithinRootCondition(column, root))) ?? sql`false`
}

function afterCredentialCursorCondition(cursor: {
  createdAt: Date
  path: string
  host: string
}): SQL<unknown> {
  /* v8 ignore next -- this cursor comparison always provides at least one SQL branch */
  return or(
    lt(credentials.createdAt, cursor.createdAt),
    and(eq(credentials.createdAt, cursor.createdAt), gt(credentials.path, cursor.path)),
    and(
      eq(credentials.createdAt, cursor.createdAt),
      eq(credentials.path, cursor.path),
      gt(credentials.host, cursor.host),
    ),
  ) ?? sql`false`
}

function isRootLevelProfile(path: string) {
  return credentialParentPath(path) === '/'
}

function appliesToRoot(profilePath: string, root: string) {
  return isAncestorOrEqual(credentialParentPath(profilePath), root)
}

function profileVisibleWithinRoot(profilePath: string, root: string) {
  return isAncestorOrEqual(root, profilePath) || appliesToRoot(profilePath, root)
}

function issuedTokenOwnerCondition(owner: {
  ownerUserId?: string | null
  orgId?: string | null
}) {
  if (owner.ownerUserId) {
    return owner.orgId
      ? and(eq(issuedTokens.ownerUserId, owner.ownerUserId), eq(issuedTokens.orgId, owner.orgId))
      : eq(issuedTokens.ownerUserId, owner.ownerUserId)
  }
  if (owner.orgId) {
    return and(isNull(issuedTokens.ownerUserId), eq(issuedTokens.orgId, owner.orgId))
  }
  return sql`false`
}

// ─── Cred Profiles ──────────────────────────────────────────────────────────

export async function getCredProfile(db: Database, path: string) {
  const rows = await db.select().from(credProfiles).where(eq(credProfiles.path, path))
  const row = rows[0]
  if (!row) return null
  return { ...row, host: normalizeHostList(row.host) }
}

export async function getCredProfileByHost(db: Database, host: string) {
  const profiles = await listCredProfiles(db)
  return profiles.find(profile => profile.host.includes(host)) ?? null
}

export async function getCredProfilesByHostWithinRoot(db: Database, host: string, root: string) {
  const profiles = await listCredProfiles(db)
  return profiles
    .filter(profile => profile.host.includes(host) && appliesToRoot(profile.path, root))
    .sort(compareByDeepestPath)
}

export async function getCredProfilesBySlugWithinRoot(db: Database, slug: string, root: string) {
  const profiles = await listCredProfiles(db)
  return profiles
    .filter(profile => credentialName(profile.path) === slug && appliesToRoot(profile.path, root))
    .sort(compareByDeepestPath)
}

export async function getCredProfilesBySlugAndHost(db: Database, slug: string, host: string) {
  const profiles = await listCredProfiles(db)
  return profiles
    .filter(profile => credentialName(profile.path) === slug && profile.host.includes(host))
    .sort(compareByDeepestPath)
}

export async function getCredProfilesByHostWithPublicFallback(
  db: Database,
  host: string,
  root: string,
) {
  const matches = await getCredProfilesByHostWithinRoot(db, host, root)
  const local = matches.filter(profile => !isRootLevelProfile(profile.path))
  if (local.length > 0) {
    return local
  }
  return matches.filter(profile => isRootLevelProfile(profile.path))
}

export async function getCredProfilesBySlugWithPublicFallback(
  db: Database,
  slug: string,
  root: string,
) {
  const matches = await getCredProfilesBySlugWithinRoot(db, slug, root)
  const local = matches.filter(profile => !isRootLevelProfile(profile.path))
  if (local.length > 0) {
    return local
  }
  return matches.filter(profile => isRootLevelProfile(profile.path))
}

export async function listCredProfiles(db: Database): Promise<CredProfileRow[]> {
  const rows = await db.select().from(credProfiles)
  return rows.map(row => ({ ...row, host: normalizeHostList(row.host) }))
}

export async function listCredProfilesPage(
  db: Database,
  options: {
    limit: number
    afterPath?: string | null
    visibleRoots: string[]
  },
) {
  if (options.visibleRoots.length === 0) {
    return takePage([], options.limit)
  }

  const profiles = await listCredProfiles(db)
  const visible = profiles
    .filter(profile => options.visibleRoots.some(root => profileVisibleWithinRoot(profile.path, root)))
    .filter(profile => options.afterPath ? profile.path > options.afterPath : true)
    .sort((a, b) => a.path.localeCompare(b.path))

  return takePage(visible, options.limit)
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
  path: string,
  data: {
    host: string[]
    auth?: Record<string, unknown>
    managedOauth?: Record<string, unknown>
    displayName?: string
    description?: string
  },
) {
  await db
    .insert(credProfiles)
    .values({
      path,
      host: data.host,
      auth: data.auth,
      managedOauth: data.managedOauth,
      displayName: data.displayName,
      description: data.description,
    })
    .onConflictDoUpdate({
      target: credProfiles.path,
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

export async function deleteCredProfile(db: Database, path: string) {
  const result = await db.delete(credProfiles).where(eq(credProfiles.path, path)).returning()
  return result.length > 0
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

export async function listCredentials(db: Database): Promise<CredentialRow[]> {
  return db.select().from(credentials)
}

export async function listCredentialsWithinRoots(
  db: Database,
  roots: string[],
) {
  const all = await listCredentials(db)
  return all.filter(credential =>
    roots.some(root => isAncestorOrEqual(root, credential.path)),
  )
}

export async function listCredentialsAccessible(
  db: Database,
  roots: string[],
) {
  return listCredentialsWithinRoots(db, roots)
}

export async function listCredentialsAccessiblePage(
  db: Database,
  options: {
    limit: number
    roots: string[]
    pathPrefix?: string
    after?: {
      createdAt: Date
      path: string
      host: string
    } | null
  },
) {
  if (options.roots.length === 0) {
    return takePage([], options.limit)
  }

  const conditions: SQL<unknown>[] = [
    pathWithinAnyRootCondition(credentials.path, options.roots),
  ]
  if (options.pathPrefix) {
    conditions.push(pathWithinRootCondition(credentials.path, options.pathPrefix))
  }
  if (options.after) {
    conditions.push(afterCredentialCursorCondition(options.after))
  }

  const rows = await db
    .select()
    .from(credentials)
    .where(and(...conditions))
    .orderBy(desc(credentials.createdAt), asc(credentials.path), asc(credentials.host))
    .limit(options.limit + 1)

  return takePage(rows, options.limit)
}

export async function getCredentialsByHostWithinRoot(
  db: Database,
  host: string,
  root: string,
) {
  const candidates = await getCredentialsByHost(db, host)
  return candidates
    .filter(credential => isAncestorOrEqual(root, credential.path))
    .sort(compareByDeepestPath)
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

export async function moveCredential(
  db: Database,
  host: string,
  oldPath: string,
  newPath: string,
) {
  const result = await db
    .update(credentials)
    .set({ path: newPath, updatedAt: sql`now()` })
    .where(and(eq(credentials.host, host), eq(credentials.path, oldPath)))
    .returning()
  return result.length > 0
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

// ─── Issued Tokens ───────────────────────────────────────────────────────────

export interface CreateIssuedTokenData {
  id: string
  ownerUserId?: string | null
  orgId?: string | null
  name?: string | null
  tokenHash: string
  revocationIds: string[]
  rights: TokenRight[]
  constraints: TokenConstraint[]
  expiresAt?: Date | null
}

export async function createIssuedToken(db: Database, data: CreateIssuedTokenData) {
  const rows = await db
    .insert(issuedTokens)
    .values({
      id: data.id,
      ownerUserId: data.ownerUserId ?? null,
      orgId: data.orgId ?? null,
      name: data.name ?? null,
      tokenHash: data.tokenHash,
      revocationIds: data.revocationIds,
      rights: data.rights,
      constraints: data.constraints,
      expiresAt: data.expiresAt ?? null,
    })
    .returning()

  return rows[0] ?? null
}

export async function listIssuedTokensByOwner(
  db: Database,
  owner: { ownerUserId?: string | null; orgId?: string | null },
) {
  return db
    .select()
    .from(issuedTokens)
    .where(issuedTokenOwnerCondition(owner))
    .orderBy(desc(issuedTokens.createdAt), desc(issuedTokens.id))
}

export async function getIssuedTokenById(
  db: Database,
  id: string,
  owner: { ownerUserId?: string | null; orgId?: string | null },
) {
  const rows = await db
    .select()
    .from(issuedTokens)
    .where(and(eq(issuedTokens.id, id), issuedTokenOwnerCondition(owner)))

  return rows[0] ?? null
}

export async function getIssuedTokenByHash(db: Database, tokenHash: string) {
  const rows = await db
    .select()
    .from(issuedTokens)
    .where(eq(issuedTokens.tokenHash, tokenHash))

  return rows[0] ?? null
}

export function isMissingIssuedTokensTableError(error: unknown) {
  if (
    typeof error === 'object' &&
    error !== null &&
    'cause' in error &&
    error.cause &&
    isMissingIssuedTokensTableError(error.cause)
  ) {
    return true
  }

  const code =
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
      ? error.code
      : null
  if (code === '42P01') {
    return true
  }

  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : ''
  return message.includes('issued_tokens') && (
    message.includes('does not exist') ||
    message.includes('relation') ||
    message.includes('no such table')
  )
}

export async function markIssuedTokenUsed(
  db: Database,
  tokenHash: string,
  usedAt = new Date(),
) {
  const rows = await db
    .update(issuedTokens)
    .set({ lastUsedAt: usedAt })
    .where(eq(issuedTokens.tokenHash, tokenHash))
    .returning()

  return rows[0] ?? null
}

export async function markIssuedTokenUsedBestEffort(
  db: Database,
  tokenHash: string,
  usedAt = new Date(),
) {
  try {
    return await markIssuedTokenUsed(db, tokenHash, usedAt)
  } catch (error) {
    if (isMissingIssuedTokensTableError(error)) {
      return null
    }
    throw error
  }
}

export async function revokeIssuedTokenById(
  db: Database,
  id: string,
  owner: { ownerUserId?: string | null; orgId?: string | null },
  reason?: string,
) {
  const revokedAt = new Date()

  return db.transaction(async tx => {
    const rows = await tx
      .select()
      .from(issuedTokens)
      .where(and(eq(issuedTokens.id, id), issuedTokenOwnerCondition(owner)))

    const token = rows[0] ?? null
    if (!token) return null

    await tx
      .update(issuedTokens)
      .set({
        revokedAt: token.revokedAt ?? revokedAt,
        revokeReason: token.revokeReason ?? reason ?? null,
      })
      .where(eq(issuedTokens.id, token.id))

    if (token.revocationIds.length > 0) {
      await tx
        .insert(revocations)
        .values(token.revocationIds.map(revocationId => ({ revocationId, reason })))
        .onConflictDoNothing()
    }

    const updated = await tx
      .select()
      .from(issuedTokens)
      .where(eq(issuedTokens.id, token.id))

    return updated[0] ?? token
  })
}

// ─── Auth Flows ──────────────────────────────────────────────────────────────

export interface CreateFlowData {
  id: string
  profilePath?: string
  method: 'oauth' | 'api_key'
  codeVerifier?: string
  scopePath?: string
  expiresAt: Date
}

function formatTimestampWithoutTimezone(date: Date) {
  // auth_flows.expires_at is TIMESTAMP WITHOUT TIME ZONE in the current schema,
  // and PGlite reads that type back as a UTC instant. Persist the UTC wall-clock
  // components explicitly so the same absolute instant round-trips regardless
  // of the process timezone or the session timezone.
  const pad = (value: number, width = 2) => value.toString().padStart(width, '0')
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${pad(date.getUTCMilliseconds(), 3)}`
}

function asTimestampWithoutTimezone(date: Date) {
  return sql`${formatTimestampWithoutTimezone(date)}::timestamp`
}

export interface CompleteFlowData {
  token?: string
  identity: string
}

export async function createAuthFlow(db: Database, data: CreateFlowData) {
  await db.insert(authFlows).values({
    id: data.id,
    profilePath: data.profilePath,
    method: data.method,
    codeVerifier: data.codeVerifier,
    scopePath: data.scopePath,
    expiresAt: asTimestampWithoutTimezone(data.expiresAt),
  })
}

export async function updateAuthFlow(db: Database, id: string, data: CreateFlowData) {
  await db
    .update(authFlows)
    .set({
      profilePath: data.profilePath,
      method: data.method,
      codeVerifier: data.codeVerifier,
      scopePath: data.scopePath,
      expiresAt: asTimestampWithoutTimezone(data.expiresAt),
    })
    .where(eq(authFlows.id, id))
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
