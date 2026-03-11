import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import {
  listCredProfiles,
  getCredProfile,
  upsertCredProfile,
  deleteCredProfile,
} from '../db/queries'
import { RESERVED_PATHS } from '../lib/utils'
import { credentialName, isAncestorOrEqual, validatePath } from '../paths'
import { hasRightForPath, rootsForAction, rootsForActions } from '../rights'
import {
  buildListPageSchema,
  InvalidPaginationCursorError,
  paginateItems,
  PaginationQuerySchema,
} from '../lib/pagination'

export const CredProfileSchema = z.object({
  slug: z.string().meta({ description: 'Unique profile identifier', example: 'linear' }),
  host: z.array(z.string()).meta({ description: 'Hostnames this profile applies to', example: ['api.linear.app'] }),
  path: z.string().meta({ description: 'Path in the hierarchy', example: '/' }),
  displayName: z.string().nullable().meta({ description: 'Human-readable display name' }),
  description: z.string().nullable().meta({ description: 'Profile description' }),
}).meta({ id: 'CredProfile' })

export const CredProfileDetailSchema = CredProfileSchema.extend({
  auth: z.unknown().nullable().meta({ description: 'Auth configuration (OAuth or headers)' }),
}).meta({ id: 'CredProfileDetail' })

export const CredProfileListPageSchema = buildListPageSchema(CredProfileSchema, 'CredProfileListPage')

export const CreateCredProfileRequestSchema = z.object({
  host: z.array(z.string()).min(1).meta({ description: 'Hostnames this profile applies to' }),
  path: z.string().optional().meta({ description: 'Path for this profile (defaults to token path)', example: '/' }),
  auth: z.record(z.string(), z.unknown()).optional().meta({ description: 'Auth configuration' }),
  managedOauth: z.record(z.string(), z.unknown()).optional().meta({ description: 'Managed OAuth config' }),
  displayName: z.string().optional().meta({ description: 'Human-readable display name' }),
  description: z.string().optional().meta({ description: 'Profile description' }),
}).meta({ id: 'CreateCredProfileRequest' })

export const ErrorSchema = z.object({
  error: z.string().meta({ example: 'Profile not found' }),
}).meta({ id: 'Error' })

export const OkSchema = z.object({
  ok: z.literal(true),
}).meta({ id: 'Ok' })

export const OkWithSlugSchema = OkSchema.extend({
  slug: z.string(),
}).meta({ id: 'OkWithSlug' })

export const credProfileRoutes = new Hono<CoreHonoEnv>()

credProfileRoutes.get('/', requireToken,
  describeRoute({
    tags: ['cred_profiles'],
    summary: 'List credential profiles',
    description: 'List credential profiles visible to this token with cursor-based pagination.',
    responses: {
      200: { description: 'Paginated list of profiles', content: { 'application/json': { schema: resolver(CredProfileListPageSchema) } } },
      400: { description: 'Invalid pagination cursor', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  zValidator('query', PaginationQuerySchema),
  async c => {
    const db = c.get('db')
    const facts = c.get('tokenFacts')
    const roots = facts
      ? rootsForActions(facts.rights, ['credential.use', 'credential.bootstrap', 'profile.manage'])
      : []
    const query = c.req.valid('query')
    const allProfiles = await listCredProfiles(db)

    const visible = allProfiles.filter(profile =>
      roots.some(root => isAncestorOrEqual(root, profile.path)),
    ).map(p => ({
        slug: p.path,
        host: p.host,
        path: p.path,
        displayName: p.displayName,
        description: p.description,
      }))
      .sort((a, b) => a.path.localeCompare(b.path))

    try {
      return c.json(paginateItems({
        items: visible,
        limit: query.limit,
        cursor: query.cursor,
        compareToCursor: (item, cursor: { slug: string }) => item.slug.localeCompare(cursor.slug),
        toCursor: item => ({ slug: item.slug }),
      }))
    } catch (error) {
      if (error instanceof InvalidPaginationCursorError) {
        return c.json({ error: error.message }, 400)
      }
      throw error
    }
  },
)

credProfileRoutes.get('/:slug', requireToken,
  describeRoute({
    tags: ['cred_profiles'],
    summary: 'Get credential profile',
    description: 'Get a credential profile by slug.',
    responses: {
      200: { description: 'Profile details', content: { 'application/json': { schema: resolver(CredProfileDetailSchema) } } },
      404: { description: 'Profile not found', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  async c => {
    const slug = c.req.param('slug')
    const db = c.get('db')
    const requestedPath = c.req.query('path') ?? `/${slug}`

    if (!validatePath(requestedPath)) {
      return c.json({ error: 'Invalid path' }, 400)
    }

    const profile = await getCredProfile(db, requestedPath)
    if (!profile) return c.json({ error: 'Profile not found' }, 404)

    const facts = c.get('tokenFacts')
    if (!facts) return c.json({ error: 'Forbidden' }, 403)
    const visibleRoots = rootsForActions(facts.rights, ['credential.use', 'credential.bootstrap', 'profile.manage'])
    if (!visibleRoots.some(root => isAncestorOrEqual(root, profile.path))) {
      return c.json({ error: 'Profile not found' }, 404)
    }

    return c.json({
      slug: profile.path,
      host: profile.host,
      path: profile.path,
      displayName: profile.displayName,
      description: profile.description,
      auth: profile.auth ?? null,
    })
  },
)

credProfileRoutes.put('/:slug', requireToken,
  describeRoute({
    tags: ['cred_profiles'],
    summary: 'Create or update credential profile',
    description: 'Register a new credential profile or update an existing one by slug.',
    responses: {
      200: { description: 'Profile created or updated', content: { 'application/json': { schema: resolver(OkWithSlugSchema) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  zValidator('json', CreateCredProfileRequestSchema),
  async c => {
    const facts = c.get('tokenFacts')
    if (!facts) return c.json({ error: 'Forbidden' }, 403)
    const slug = c.req.param('slug')
    if (RESERVED_PATHS.has(slug)) {
      return c.json({ error: `'${slug}' is a reserved name` }, 400)
    }

    const body = c.req.valid('json')
    const manageRoots = rootsForAction(facts.rights, 'profile.manage')

    let profilePath = body.path
    if (!profilePath) {
      if (manageRoots.length === 0) {
        return c.json({ error: 'Forbidden: requires "profile.manage" right' }, 403)
      }
      if (manageRoots.length > 1) {
        return c.json({
          error: 'Profile path is required when multiple management roots are granted',
          roots: manageRoots,
        }, 409)
      }
      profilePath = `${manageRoots[0] === '/' ? '' : manageRoots[0]}/${slug}`
    }

    if (!validatePath(profilePath)) {
      return c.json({ error: 'Invalid path' }, 400)
    }
    if (credentialName(profilePath) !== slug) {
      return c.json({ error: 'Profile path must end with the route slug' }, 400)
    }

    if (!hasRightForPath(facts.rights, 'profile.manage', profilePath)) {
      return c.json({ error: `Forbidden: requires "profile.manage" for '${profilePath}'` }, 403)
    }

    const db = c.get('db')
    const existing = await getCredProfile(db, profilePath)
    /* v8 ignore start -- existing.path equals profilePath, so the earlier profilePath right check already covers this guard */
    if (existing && !hasRightForPath(facts.rights, 'profile.manage', existing.path)) {
      return c.json({ error: `Forbidden: requires "profile.manage" for '${existing.path}'` }, 403)
    }
    /* v8 ignore stop */

    const displayName = body.displayName ?? slug.charAt(0).toUpperCase() + slug.slice(1)

    await upsertCredProfile(db, profilePath, {
      host: body.host,
      auth: body.auth,
      managedOauth: body.managedOauth,
      displayName,
      description: body.description,
    })

    return c.json({ ok: true as const, slug })
  },
)

credProfileRoutes.delete('/:slug', requireToken,
  describeRoute({
    tags: ['cred_profiles'],
    summary: 'Delete credential profile',
    description: 'Remove a credential profile by slug.',
    responses: {
      200: { description: 'Profile deleted', content: { 'application/json': { schema: resolver(OkSchema) } } },
      404: { description: 'Profile not found', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  async c => {
    const facts = c.get('tokenFacts')
    if (!facts) return c.json({ error: 'Forbidden' }, 403)
    const db = c.get('db')
    const slug = c.req.param('slug')
    const manageRoots = rootsForAction(facts.rights, 'profile.manage')
    let requestedPath = c.req.query('path')
    if (!requestedPath) {
      if (manageRoots.length === 0) {
        return c.json({ error: 'Forbidden: requires "profile.manage" right' }, 403)
      }
      if (manageRoots.length > 1) {
        return c.json({
          error: 'Profile path is required when multiple management roots are granted',
          roots: manageRoots,
        }, 409)
      }
      requestedPath = `${manageRoots[0] === '/' ? '' : manageRoots[0]}/${slug}`
    }
    if (!validatePath(requestedPath)) {
      return c.json({ error: 'Invalid path' }, 400)
    }
    const existing = await getCredProfile(db, requestedPath)
    if (!existing) return c.json({ error: 'Profile not found' }, 404)

    if (!hasRightForPath(facts.rights, 'profile.manage', existing.path)) {
      return c.json({ error: `Forbidden: requires "profile.manage" for '${existing.path}'` }, 403)
    }

    const deleted = await deleteCredProfile(db, requestedPath)
    if (!deleted) return c.json({ error: 'Profile not found' }, 404)
    return c.json({ ok: true as const })
  },
)
