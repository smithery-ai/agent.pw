import {
  and,
  asc,
  desc,
  eq,
  gt,
  inArray,
  isNull,
  like,
  lt,
  sql,
  type InferSelectModel,
  type SQL,
} from 'drizzle-orm'
import type {
  TokenConstraint,
  TokenRight,
} from '../types.js'
import {
  ancestorPaths,
  credentialName,
  credentialParentPath,
  isAncestorOrEqual,
  joinCredentialPath,
  pathDepth,
} from '../paths.js'
import type { Database } from './index.js'
import {
  credProfiles,
  credentials,
  issuedTokens,
  revocations,
} from './schema/index.js'

type CredProfileModel = InferSelectModel<typeof credProfiles>
type CredentialModel = InferSelectModel<typeof credentials>

export type CredProfileRow = Omit<CredProfileModel, 'host'> & {
  host: string[]
}

export type CredentialRow = CredentialModel

function normalizeHostList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
  }
  if (typeof value === 'string' && value.length > 0) {
    return [value]
  }
  return []
}

function normalizeProfile(row: CredProfileModel): CredProfileRow {
  return {
    ...row,
    host: normalizeHostList(row.host),
  }
}

function compareByDeepestPath<T extends { path: string }>(a: T, b: T) {
  return pathDepth(b.path) - pathDepth(a.path) || a.path.localeCompare(b.path)
}

function pathWithinRootCondition(
  column: typeof credProfiles.path | typeof credentials.path,
  root: string,
): SQL<unknown> {
  if (root === '/') {
    return sql`true`
  }

  return sql`(${eq(column, root)} or ${like(column, `${root}/%`)})`
}

function afterCredentialCursorCondition(cursor: {
  createdAt: Date
  path: string
  host: string
}): SQL<unknown> {
  return sql`(
    ${lt(credentials.createdAt, cursor.createdAt)}
    or ${and(eq(credentials.createdAt, cursor.createdAt), gt(credentials.path, cursor.path))}
    or ${and(
      eq(credentials.createdAt, cursor.createdAt),
      eq(credentials.path, cursor.path),
      gt(credentials.host, cursor.host),
    )}
  )`
}

function hostContainsCondition(host: string): SQL<unknown> {
  return sql`${credProfiles.host} ? ${host}`
}

function rootLevelProfileCondition(): SQL<unknown> {
  return sql`(length(${credProfiles.path}) - length(replace(${credProfiles.path}, '/', ''))) = 1`
}

function rootLevelCredentialCondition(): SQL<unknown> {
  return sql`(length(${credentials.path}) - length(replace(${credentials.path}, '/', ''))) = 1`
}

function profileApplicabilityCondition(root: string): SQL<unknown> {
  const ancestors = ancestorPaths(root)
  const localRoots = ancestors.filter(candidate => candidate !== '/')
  const conditions: SQL<unknown>[] = [rootLevelProfileCondition()]

  for (const candidate of localRoots) {
    conditions.push(pathWithinRootCondition(credProfiles.path, candidate))
  }

  return sql`(${sql.join(conditions, sql` or `)})`
}

function appliesToRoot(profilePath: string, root: string) {
  return isAncestorOrEqual(credentialParentPath(profilePath), root)
}

function credentialApplicabilityCondition(root: string): SQL<unknown> {
  const ancestors = ancestorPaths(root)
  const localRoots = ancestors.filter(candidate => candidate !== '/')
  const conditions: SQL<unknown>[] = [rootLevelCredentialCondition()]

  for (const candidate of localRoots) {
    conditions.push(pathWithinRootCondition(credentials.path, candidate))
  }

  return sql`(${sql.join(conditions, sql` or `)})`
}

function credentialAppliesToRoot(credentialPath: string, root: string) {
  return isAncestorOrEqual(credentialParentPath(credentialPath), root)
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

function takePage<T>(rows: T[], limit: number) {
  return {
    items: rows.slice(0, limit),
    hasMore: rows.length > limit,
  }
}

// ─── Credential Profiles ─────────────────────────────────────────────────────

export async function getCredProfile(db: Database, path: string) {
  const rows = await db.select().from(credProfiles).where(eq(credProfiles.path, path))
  const row = rows[0]
  return row ? normalizeProfile(row) : null
}

export async function listCredProfiles(
  db: Database,
  options: {
    root?: string
  } = {},
): Promise<CredProfileRow[]> {
  const root = options.root ?? '/'
  const conditions = root === '/'
    ? undefined
    : pathWithinRootCondition(credProfiles.path, root)
  const rows = await db.select().from(credProfiles).where(conditions)
  return rows.map(normalizeProfile).sort((a, b) => a.path.localeCompare(b.path))
}

export async function getCredProfilesByProviderWithinRoot(
  db: Database,
  provider: string,
  root: string,
) {
  const candidatePaths = ancestorPaths(root).map(candidate => joinCredentialPath(candidate, provider))
  const rows = await db
    .select()
    .from(credProfiles)
    .where(inArray(credProfiles.path, candidatePaths))

  return rows
    .map(normalizeProfile)
    .filter(profile => credentialName(profile.path) === provider)
    .sort(compareByDeepestPath)
}

export async function getCredProfilesByHostWithinRoot(
  db: Database,
  host: string,
  root: string,
) {
  const rows = await db
    .select()
    .from(credProfiles)
    .where(and(profileApplicabilityCondition(root), hostContainsCondition(host)))

  return rows
    .map(normalizeProfile)
    .filter(profile => appliesToRoot(profile.path, root))
    .sort(compareByDeepestPath)
}

export async function upsertCredProfile(
  db: Database,
  path: string,
  data: {
    host: string[]
    auth?: Record<string, unknown>
    oauthConfig?: Record<string, unknown>
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
      oauthConfig: data.oauthConfig,
      displayName: data.displayName,
      description: data.description,
    })
    .onConflictDoUpdate({
      target: credProfiles.path,
      set: {
        host: sql`excluded.host`,
        auth: sql`coalesce(excluded.auth, ${credProfiles.auth})`,
        oauthConfig: sql`coalesce(excluded.oauth_config, ${credProfiles.oauthConfig})`,
        displayName: sql`coalesce(excluded.display_name, ${credProfiles.displayName})`,
        description: sql`coalesce(excluded.description, ${credProfiles.description})`,
        updatedAt: sql`now()`,
      },
    })
}

export async function deleteCredProfile(db: Database, path: string) {
  const rows = await db.delete(credProfiles).where(eq(credProfiles.path, path)).returning()
  return rows.length > 0
}

// ─── Credentials ─────────────────────────────────────────────────────────────

export async function getCredential(db: Database, host: string, path: string) {
  const rows = await db
    .select()
    .from(credentials)
    .where(and(eq(credentials.host, host), eq(credentials.path, path)))

  return rows[0] ?? null
}

export async function listCredentials(
  db: Database,
  options: {
    root?: string
  } = {},
): Promise<CredentialRow[]> {
  const root = options.root ?? '/'
  const conditions = root === '/'
    ? undefined
    : pathWithinRootCondition(credentials.path, root)
  const rows = await db.select().from(credentials).where(conditions)
  return rows.sort((a, b) => a.path.localeCompare(b.path) || a.host.localeCompare(b.host))
}

export async function getCredentialsByHostWithinRoot(
  db: Database,
  host: string,
  root: string,
) {
  const rows = await db
    .select()
    .from(credentials)
    .where(and(eq(credentials.host, host), credentialApplicabilityCondition(root)))

  return rows
    .filter(credential => credentialAppliesToRoot(credential.path, root))
    .sort(compareByDeepestPath)
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

  const conditions: SQL<unknown>[] = []
  const roots = options.roots.map(root => pathWithinRootCondition(credentials.path, root))
  conditions.push(sql`(${sql.join(roots, sql` or `)})`)
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
  const rows = await db
    .update(credentials)
    .set({ path: newPath, updatedAt: sql`now()` })
    .where(and(eq(credentials.host, host), eq(credentials.path, oldPath)))
    .returning()

  return rows.length > 0
}

export async function deleteCredential(db: Database, host: string, path: string) {
  const rows = await db
    .delete(credentials)
    .where(and(eq(credentials.host, host), eq(credentials.path, path)))
    .returning()

  return rows.length > 0
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

  const [row = null] = rows
  return row
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

export async function getIssuedTokenByIdUnscoped(db: Database, id: string) {
  const rows = await db
    .select()
    .from(issuedTokens)
    .where(eq(issuedTokens.id, id))

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
  const token = await getIssuedTokenById(db, id, owner)
  if (!token) return null

  return revokeIssuedTokenByIdUnscoped(db, id, reason)
}

export async function revokeIssuedTokenByIdUnscoped(
  db: Database,
  id: string,
  reason?: string,
) {
  const revokedAt = new Date()

  return db.transaction(async tx => {
    const rows = await tx
      .select()
      .from(issuedTokens)
      .where(eq(issuedTokens.id, id))

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

    const [row = token] = updated
    return row
  })
}
