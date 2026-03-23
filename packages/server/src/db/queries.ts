import {
  and,
  asc,
  desc,
  eq,
  gt,
  inArray,
  like,
  lt,
  sql,
  type InferSelectModel,
  type SQL,
} from 'drizzle-orm'
import {
  ancestorPaths,
  credentialName,
  credentialParentPath,
  isAncestorOrEqual,
  joinCredentialPath,
  pathDepth,
} from '../paths.js'
import type { SqlNamespaceOptions } from '../types.js'
import type { Database } from './index.js'
import {
  coerceSqlNamespace,
  type credentials,
  type credProfiles,
  type AgentPwSqlNamespace,
} from './schema/index.js'

type DefaultCredProfileModel = InferSelectModel<typeof credProfiles>
type DefaultCredentialModel = InferSelectModel<typeof credentials>

export type CredProfileRow = Omit<DefaultCredProfileModel, 'host'> & {
  host: string[]
}

export type CredentialRow = DefaultCredentialModel

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace

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

function appliesToRoot(profilePath: string, root: string) {
  return isAncestorOrEqual(credentialParentPath(profilePath), root)
}

function credentialAppliesToRoot(credentialPath: string, root: string) {
  return isAncestorOrEqual(credentialParentPath(credentialPath), root)
}

function takePage<T>(rows: T[], limit: number) {
  return {
    items: rows.slice(0, limit),
    hasMore: rows.length > limit,
  }
}

export function createQueryHelpers(namespaceInput?: SqlNamespaceInput) {
  const sqlNamespace = coerceSqlNamespace(namespaceInput)
  const { credProfiles, credentials } = sqlNamespace.tables

  type CredProfileModel = InferSelectModel<typeof credProfiles>
  function normalizeProfile(row: CredProfileModel): CredProfileRow {
    return {
      ...row,
      host: normalizeHostList(row.host),
    }
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
    host: string | null
  }): SQL<unknown> {
    return sql`(
      ${lt(credentials.createdAt, cursor.createdAt)}
      or ${and(eq(credentials.createdAt, cursor.createdAt), gt(credentials.path, cursor.path))}
      or ${and(
        eq(credentials.createdAt, cursor.createdAt),
        eq(credentials.path, cursor.path),
        gt(sql`coalesce(${credentials.host}, '')`, cursor.host ?? ''),
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

  function credentialApplicabilityCondition(root: string): SQL<unknown> {
    const ancestors = ancestorPaths(root)
    const localRoots = ancestors.filter(candidate => candidate !== '/')
    const conditions: SQL<unknown>[] = [rootLevelCredentialCondition()]

    for (const candidate of localRoots) {
      conditions.push(pathWithinRootCondition(credentials.path, candidate))
    }

    return sql`(${sql.join(conditions, sql` or `)})`
  }

  async function getCredProfile(db: Database, path: string) {
    const rows = await db.select().from(credProfiles).where(eq(credProfiles.path, path))
    const row = rows[0]
    return row ? normalizeProfile(row) : null
  }

  async function listCredProfiles(
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

  async function getCredProfilesByProviderWithinRoot(
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

  async function getCredProfilesByHostWithinRoot(
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

  async function upsertCredProfile(
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

  async function deleteCredProfile(db: Database, path: string) {
    const rows = await db.delete(credProfiles).where(eq(credProfiles.path, path)).returning()
    return rows.length > 0
  }

  async function getCredential(db: Database, path: string) {
    const rows = await db
      .select()
      .from(credentials)
      .where(eq(credentials.path, path))

    return rows[0] ?? null
  }

  async function listCredentials(
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
    return rows.sort((a, b) => a.path.localeCompare(b.path))
  }

  async function getCredentialsByProfileWithinRoot(
    db: Database,
    profilePath: string,
    root: string,
  ) {
    const rows = await db
      .select()
      .from(credentials)
      .where(and(eq(credentials.profilePath, profilePath), credentialApplicabilityCondition(root)))

    return rows
      .filter(credential => credentialAppliesToRoot(credential.path, root))
      .sort(compareByDeepestPath)
  }

  async function getCredentialsByHostWithinRoot(
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

  async function listCredentialsAccessiblePage(
    db: Database,
    options: {
      limit: number
      roots: string[]
      pathPrefix?: string
      after?: {
        createdAt: Date
        path: string
        host: string | null
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
      .orderBy(desc(credentials.createdAt), asc(credentials.path), asc(sql`coalesce(${credentials.host}, '')`))
      .limit(options.limit + 1)

    return takePage(rows, options.limit)
  }

  async function upsertCredential(
    db: Database,
    data: {
      profilePath: string
      host?: string | null
      path: string
      auth: Record<string, unknown>
      secret: Buffer
    },
  ) {
    await db
      .insert(credentials)
      .values({
        profilePath: data.profilePath,
        host: data.host,
        path: data.path,
        auth: data.auth,
        secret: data.secret,
      })
      .onConflictDoUpdate({
        target: [credentials.path],
        set: {
          profilePath: sql`excluded.profile_path`,
          host: sql`excluded.host`,
          auth: sql`excluded.auth`,
          secret: sql`excluded.secret`,
          updatedAt: sql`now()`,
        },
      })
  }

  async function moveCredential(
    db: Database,
    oldPath: string,
    newPath: string,
  ) {
    const rows = await db
      .update(credentials)
      .set({ path: newPath, updatedAt: sql`now()` })
      .where(eq(credentials.path, oldPath))
      .returning()

    return rows.length > 0
  }

  async function deleteCredential(db: Database, path: string) {
    const rows = await db
      .delete(credentials)
      .where(eq(credentials.path, path))
      .returning()

    return rows.length > 0
  }

  return {
    getCredProfile,
    listCredProfiles,
    getCredProfilesByProviderWithinRoot,
    getCredProfilesByHostWithinRoot,
    upsertCredProfile,
    deleteCredProfile,
    getCredential,
    listCredentials,
    getCredentialsByProfileWithinRoot,
    getCredentialsByHostWithinRoot,
    listCredentialsAccessiblePage,
    upsertCredential,
    moveCredential,
    deleteCredential,
  }
}

const defaultQueryHelpers = createQueryHelpers()

export const getCredProfile = defaultQueryHelpers.getCredProfile
export const listCredProfiles = defaultQueryHelpers.listCredProfiles
export const getCredProfilesByProviderWithinRoot = defaultQueryHelpers.getCredProfilesByProviderWithinRoot
export const getCredProfilesByHostWithinRoot = defaultQueryHelpers.getCredProfilesByHostWithinRoot
export const upsertCredProfile = defaultQueryHelpers.upsertCredProfile
export const deleteCredProfile = defaultQueryHelpers.deleteCredProfile
export const getCredential = defaultQueryHelpers.getCredential
export const listCredentials = defaultQueryHelpers.listCredentials
export const getCredentialsByProfileWithinRoot = defaultQueryHelpers.getCredentialsByProfileWithinRoot
export const getCredentialsByHostWithinRoot = defaultQueryHelpers.getCredentialsByHostWithinRoot
export const listCredentialsAccessiblePage = defaultQueryHelpers.listCredentialsAccessiblePage
export const upsertCredential = defaultQueryHelpers.upsertCredential
export const moveCredential = defaultQueryHelpers.moveCredential
export const deleteCredential = defaultQueryHelpers.deleteCredential
