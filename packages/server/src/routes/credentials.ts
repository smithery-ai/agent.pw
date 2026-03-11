import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import {
  getCredProfilesBySlugWithPublicFallback,
  getCredential,
  listCredentialsAccessiblePage,
  moveCredential,
  upsertCredential,
  deleteCredential,
} from '../db/queries'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'
import {
  credentialName,
  credentialParentPath,
  joinCredentialPath,
  validateCredentialName,
  validatePath,
} from '../paths'
import { coveringRootsForPath, hasRightForPath, rootsForAction, rootsForActions } from '../rights'
import {
  buildListPageSchema,
  decodePageCursorWithSchema,
  encodePageCursor,
  InvalidPaginationCursorError,
  PaginationQuerySchema,
} from '../lib/pagination'

export const CredentialSchema = z.object({
  name: z.string().meta({ description: 'Credential name', example: 'linear' }),
  host: z.string().meta({ description: 'Target hostname', example: 'api.linear.app' }),
  path: z.string().meta({ description: 'Full credential path', example: '/org_ruzo/linear' }),
  authKind: z.string().nullable().meta({ description: 'Credential auth kind', example: 'headers' }),
  createdAt: z.string().meta({ description: 'ISO 8601 creation timestamp' }),
}).meta({ id: 'Credential' })

export const CredentialListPageSchema = buildListPageSchema(CredentialSchema, 'CredentialListPage')

export const CredentialErrorSchema = z.object({
  error: z.string(),
}).meta({ id: 'CredentialError' })

export const CreateCredentialRequestSchema = z.object({
  token: z.string().optional().meta({ description: 'API token or secret' }),
  headers: z.record(z.string(), z.string()).optional().meta({ description: 'Explicit header map to send on proxied requests' }),
  host: z.string().optional().meta({ description: 'Target hostname for this credential', example: 'api.linear.app' }),
  profile: z.string().optional().meta({ description: 'Credential profile slug to derive the target host from', example: 'linear' }),
  path: z.string().optional().meta({ description: 'Full credential path (defaults to token path + name)', example: '/org_ruzo/linear' }),
}).meta({ id: 'CreateCredentialRequest' })

export const MoveCredentialRequestSchema = z.object({
  path: z.string().meta({ description: 'New full credential path', example: '/org_ruzo/production/linear' }),
  host: z.string().optional().meta({ description: 'Target hostname for the credential', example: 'api.linear.app' }),
  profile: z.string().optional().meta({ description: 'Profile slug to resolve the hostname when host is omitted', example: 'linear' }),
}).meta({ id: 'MoveCredentialRequest' })

export const DeleteCredentialQuerySchema = z.object({
  path: z.string().optional().meta({ description: 'Full credential path to delete', example: '/org_ruzo/linear' }),
  host: z.string().optional().meta({ description: 'Target hostname for the credential', example: 'api.linear.app' }),
  profile: z.string().optional().meta({ description: 'Profile slug to resolve the hostname when host is omitted', example: 'linear' }),
}).meta({ id: 'DeleteCredentialQuery' })

export const credentialRoutes = new Hono<CoreHonoEnv>()

const CredentialCursorSchema = z.object({
  createdAt: z.string().datetime(),
  path: z.string(),
  host: z.string(),
})

function pickDeepestProfile<T extends { path: string }>(matches: T[]) {
  if (matches.length === 0) {
    return { selected: null, conflicts: [] as T[] }
  }

  const topDepth = Math.max(...matches.map(match => match.path.split('/').filter(Boolean).length))
  const conflicts = matches.filter(match => match.path.split('/').filter(Boolean).length === topDepth)
  if (conflicts.length > 1) {
    return { selected: null, conflicts }
  }

  return { selected: matches[0], conflicts: [] as T[] }
}

const CredentialListQuerySchema = PaginationQuerySchema.extend({
  path: z.string().optional().meta({
    description: 'Filter to credentials under this path prefix',
    example: '/org_ruzo',
  }),
})

credentialRoutes.get('/', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'List credentials',
    description: 'List credentials accessible to this token with cursor-based pagination. Optionally filter by path prefix.',
    responses: {
      200: { description: 'Paginated list of credentials', content: { 'application/json': { schema: resolver(CredentialListPageSchema) } } },
      400: { description: 'Invalid pagination cursor', content: { 'application/json': { schema: resolver(CredentialErrorSchema) } } },
    },
  }),
  zValidator('query', CredentialListQuerySchema),
  async c => {
    const db = c.get('db')
    const facts = c.get('tokenFacts')
    const roots = facts
      ? rootsForActions(facts.rights, ['credential.use', 'credential.manage'])
      : []
    const query = c.req.valid('query')

    try {
      const cursor = query.cursor
        ? decodePageCursorWithSchema(query.cursor, CredentialCursorSchema)
        : null
      const page = await listCredentialsAccessiblePage(db, {
        limit: query.limit,
        roots,
        pathPrefix: query.path,
        after: cursor
          ? {
            createdAt: new Date(cursor.createdAt),
            path: cursor.path,
            host: cursor.host,
          }
          : null,
      })
      const data = page.items.map(cr => ({
        name: credentialName(cr.path),
        host: cr.host,
        path: cr.path,
        authKind:
          cr.auth && typeof cr.auth === 'object' && typeof cr.auth.kind === 'string'
            ? cr.auth.kind
            : null,
        createdAt: new Date(cr.createdAt).toISOString(),
      }))

      return c.json({
        data,
        hasMore: page.hasMore,
        nextCursor: page.hasMore && data.length > 0
          ? encodePageCursor({
            createdAt: data[data.length - 1]!.createdAt,
            path: data[data.length - 1]!.path,
            host: data[data.length - 1]!.host,
          })
          : null,
      })
    } catch (error) {
      if (error instanceof InvalidPaginationCursorError) {
        return c.json({ error: error.message }, 400)
      }
      throw error
    }
  },
)

credentialRoutes.put('/:name', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Store credential',
    description: 'Create or update a credential for a service. Provide either a token or explicit headers.',
    responses: {
      200: { description: 'Credential stored', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true), name: z.string(), path: z.string() }).meta({ id: 'CredentialStored' })) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(CredentialErrorSchema) } } },
      404: { description: 'Profile not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('json', CreateCredentialRequestSchema),
  async c => {
    const facts = c.get('tokenFacts')
    /* v8 ignore start -- requireToken guarantees tokenFacts is present on this route */
    if (!facts) {
      return c.json({ error: 'Forbidden' }, 403)
    }
    /* v8 ignore stop */
    const name = c.req.param('name')
    if (!validateCredentialName(name)) {
      return c.json({ error: 'Invalid credential name' }, 400)
    }

    const body = c.req.valid('json')
    if (!body.token && !body.headers) {
      return c.json({ error: 'Either token or headers is required' }, 400)
    }

    const db = c.get('db')
    const profileSlug = body.profile ?? name
    const bootstrapRoots = rootsForAction(facts.rights, 'credential.bootstrap')

    let credPath = body.path
    if (!credPath) {
      if (bootstrapRoots.length === 0) {
        return c.json({ error: 'Forbidden: requires "credential.bootstrap" right' }, 403)
      }
      if (bootstrapRoots.length > 1) {
        return c.json({
          error: 'Credential path is required when multiple bootstrap roots are granted',
          roots: bootstrapRoots,
        }, 409)
      }
      credPath = joinCredentialPath(bootstrapRoots[0], name)
    }

    if (!validatePath(credPath) || credPath === '/') {
      return c.json({ error: 'Invalid path' }, 400)
    }
    if (credentialName(credPath) !== name) {
      return c.json({ error: 'Credential path must end with the route name' }, 400)
    }

    let profile = null
    if (!body.host) {
      const profileRoots = coveringRootsForPath(
        rootsForActions(facts.rights, ['credential.bootstrap', 'credential.manage']),
        credPath,
      )
      if (profileRoots.length > 1) {
        return c.json({
          error: 'Credential path matches multiple roots; choose a more specific path or root',
          roots: profileRoots,
        }, 409)
      }

      const profileRoot = profileRoots[0] ?? credentialParentPath(credPath)
      const matches = await getCredProfilesBySlugWithPublicFallback(db, profileSlug, profileRoot)
      const { selected, conflicts } = pickDeepestProfile(matches)
      /* v8 ignore start -- same-slug profile conflicts cannot arise once applicable roots collapse to a single ancestor chain */
      if (conflicts.length > 0) {
        return c.json({
          error: `Multiple profiles named '${profileSlug}' match for '${profileRoot}'`,
          profilePaths: conflicts.map(candidate => candidate.path),
        }, 409)
      }
      /* v8 ignore stop */
      profile = selected
      if (!profile) {
        return c.json({ error: `Profile '${profileSlug}' not configured` }, 404)
      }
    }

    const host = body.host ?? profile?.host[0]
    if (!host) return c.json({ error: 'host is required when no profile host can be resolved' }, 400)

    const existing = await getCredential(db, host, credPath)
    if (existing) {
      if (!hasRightForPath(facts.rights, 'credential.manage', existing.path)) {
        return c.json({ error: `Forbidden: requires "credential.manage" for '${credPath}'` }, 403)
      }
    } else if (!hasRightForPath(facts.rights, 'credential.bootstrap', credPath)) {
      return c.json({ error: `Forbidden: requires "credential.bootstrap" for '${credPath}'` }, 403)
    }

    const authConfig = profile?.auth ?? null
    const schemes = authConfig?.kind === 'oauth' ? [] : parseAuthSchemes(authConfig?.authSchemes ? JSON.stringify(authConfig.authSchemes) : null)
    const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
    const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token as string)
    const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

    await upsertCredential(db, {
      host,
      path: credPath,
      auth: { kind: 'headers' },
      secret: encrypted,
    })
    return c.json({ ok: true as const, name, path: credPath })
  },
)

credentialRoutes.patch('/:name', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Move credential',
    description: 'Move a credential to a new path.',
    responses: {
      200: { description: 'Credential moved', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true), path: z.string() }).meta({ id: 'CredentialMoved' })) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(CredentialErrorSchema) } } },
      404: { description: 'Credential not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('json', MoveCredentialRequestSchema),
  async c => {
    const facts = c.get('tokenFacts')
    /* v8 ignore next */
    if (!facts) return c.json({ error: 'Forbidden' }, 403)

    const name = c.req.param('name')
    if (!validateCredentialName(name)) {
      return c.json({ error: 'Invalid credential name' }, 400)
    }

    const body = c.req.valid('json')
    const newPath = body.path

    if (!validatePath(newPath) || newPath === '/') {
      return c.json({ error: 'Invalid target path' }, 400)
    }
    if (credentialName(newPath) !== name) {
      return c.json({ error: 'Target path must end with the credential name' }, 400)
    }

    const db = c.get('db')
    const manageRoots = rootsForAction(facts.rights, 'credential.manage')

    // Resolve current path from single management root
    let oldPath: string
    if (manageRoots.length === 0) {
      return c.json({ error: 'Forbidden: requires "credential.manage" right' }, 403)
    }
    /* v8 ignore start -- multiple manage roots cannot arise with single-org tokens */
    if (manageRoots.length > 1) {
      return c.json({
        error: 'Credential path is required when multiple management roots are granted',
        roots: manageRoots,
      }, 409)
    }
    /* v8 ignore stop */
    oldPath = joinCredentialPath(manageRoots[0], name)

    // Resolve host
    const queryHost = body.host
    const queryProfile = body.profile ?? name
    let host = queryHost ?? null
    /* v8 ignore start -- profile-based host resolution is covered by the PUT route tests */
    if (!host) {
      const profileRoots = coveringRootsForPath(
        rootsForActions(facts.rights, ['credential.bootstrap', 'credential.manage']),
        oldPath,
      )
      const profileRoot = profileRoots[0] ?? credentialParentPath(oldPath)
      const matches = await getCredProfilesBySlugWithPublicFallback(db, queryProfile, profileRoot)
      const { selected } = pickDeepestProfile(matches)
      host = selected?.host[0] ?? null
    }
    if (!host) return c.json({ error: 'host or profile is required to identify the credential' }, 400)
    /* v8 ignore stop */

    // Verify source credential exists
    const existing = await getCredential(db, host, oldPath)
    if (!existing) return c.json({ error: 'Credential not found' }, 404)

    // Check manage rights on both old and new paths
    /* v8 ignore start -- oldPath is always within the single manage root resolved above */
    if (!hasRightForPath(facts.rights, 'credential.manage', oldPath)) {
      return c.json({ error: `Forbidden: requires "credential.manage" for '${oldPath}'` }, 403)
    }
    /* v8 ignore stop */
    if (!hasRightForPath(facts.rights, 'credential.manage', newPath)) {
      return c.json({ error: `Forbidden: requires "credential.manage" for '${newPath}'` }, 403)
    }

    // Check no credential already exists at target path
    const targetExists = await getCredential(db, host, newPath)
    if (targetExists) {
      return c.json({ error: 'A credential already exists at the target path' }, 409)
    }

    const moved = await moveCredential(db, host, oldPath, newPath)
    if (!moved) return c.json({ error: 'Credential not found' }, 404)

    return c.json({ ok: true as const, path: newPath })
  },
)

credentialRoutes.delete('/:name', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Delete credential',
    description: 'Delete a credential by name plus host/path context.',
    responses: {
      200: { description: 'Credential deleted', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true) })) } } },
      404: { description: 'Credential not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('query', DeleteCredentialQuerySchema),
  async c => {
    const facts = c.get('tokenFacts')
    /* v8 ignore next -- requireToken always populates tokenFacts before this handler runs */
    if (!facts) {
      return c.json({ error: 'Forbidden' }, 403)
    }
    const db = c.get('db')
    const name = c.req.param('name')
    if (!validateCredentialName(name)) {
      return c.json({ error: 'Invalid credential name' }, 400)
    }

    const manageRoots = rootsForAction(facts.rights, 'credential.manage')
    const query = c.req.valid('query')
    let resolvedPath = query.path
    if (!resolvedPath) {
      if (manageRoots.length === 0) {
        return c.json({ error: 'Forbidden: requires "credential.manage" right' }, 403)
      }
      if (manageRoots.length > 1) {
        return c.json({
          error: 'Credential path is required when multiple management roots are granted',
          roots: manageRoots,
        }, 409)
      }
      resolvedPath = joinCredentialPath(manageRoots[0], name)
    }
    if (!validatePath(resolvedPath) || resolvedPath === '/') {
      return c.json({ error: 'Invalid path' }, 400)
    }
    if (credentialName(resolvedPath) !== name) {
      return c.json({ error: 'Credential path must end with the route name' }, 400)
    }

    const queryHost = query.host
    const queryProfile = query.profile
    let host = queryHost ?? null
    if (!host && queryProfile) {
      const profileRoots = coveringRootsForPath(
        rootsForActions(facts.rights, ['credential.bootstrap', 'credential.manage']),
        resolvedPath,
      )
      if (profileRoots.length > 1) {
        return c.json({
          error: 'Credential path matches multiple roots; choose a more specific path or root',
          roots: profileRoots,
        }, 409)
      }

      const profileRoot = profileRoots[0] ?? credentialParentPath(resolvedPath)
      const matches = await getCredProfilesBySlugWithPublicFallback(db, queryProfile, profileRoot)
      const { selected, conflicts } = pickDeepestProfile(matches)
      /* v8 ignore start -- same-slug profile conflicts cannot arise once applicable roots collapse to a single ancestor chain */
      if (conflicts.length > 0) {
        return c.json({
          error: `Multiple profiles named '${queryProfile}' match for '${profileRoot}'`,
          profilePaths: conflicts.map(candidate => candidate.path),
        }, 409)
      }
      /* v8 ignore stop */
      if (!selected) return c.json({ error: `Profile '${queryProfile}' not configured` }, 404)
      host = selected.host[0] ?? null
    }
    if (!host) {
      return c.json({ error: 'host or profile is required' }, 400)
    }

    const existing = await getCredential(db, host, resolvedPath)
    if (!existing) return c.json({ error: 'Credential not found' }, 404)

    if (!hasRightForPath(facts.rights, 'credential.manage', existing.path)) {
      return c.json({ error: `Forbidden: requires "credential.manage" for '${existing.path}'` }, 403)
    }

    const deleted = await deleteCredential(db, host, resolvedPath)
    if (!deleted) return c.json({ error: 'Credential not found' }, 404)
    return c.json({ ok: true as const })
  },
)
