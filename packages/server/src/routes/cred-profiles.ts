import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken, requireRight } from '../core/middleware'
import {
  listCredProfiles,
  getCredProfile,
  upsertCredProfile,
  deleteCredProfile,
} from '../db/queries'
import { RESERVED_PATHS } from '../lib/utils'
import { pathFromTokenFacts, isAncestorOrEqual, validatePath, credentialParentPath } from '../paths'
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
    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') as { orgId?: string | null })
    const query = c.req.valid('query')
    const allProfiles = await listCredProfiles(db)

    // Show profiles at ancestors (usable as config) and descendants (manageable)
    const visible = allProfiles.filter(p =>
      isAncestorOrEqual(credentialParentPath(p.path), tokenPath) || isAncestorOrEqual(tokenPath, p.path),
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

    const profile = await getCredProfile(db, `/${slug}`)
    if (!profile) return c.json({ error: 'Profile not found' }, 404)

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

credProfileRoutes.put('/:slug', requireToken, requireRight('manage_services'),
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
    const slug = c.req.param('slug')
    if (RESERVED_PATHS.has(slug)) {
      return c.json({ error: `'${slug}' is a reserved name` }, 400)
    }

    const body = c.req.valid('json')

    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') as { orgId?: string | null })
    const profilePath = body.path ?? (tokenPath === '/' ? `/${slug}` : `${tokenPath}/${slug}`)

    if (!validatePath(profilePath)) {
      return c.json({ error: 'Invalid path' }, 400)
    }

    // Creation: token can only create at its own path or deeper
    if (!isAncestorOrEqual(tokenPath, profilePath)) {
      return c.json({ error: 'Cannot create profiles above your path' }, 403)
    }

    // Admin check for updates: must be at or above existing profile's path
    const db = c.get('db')
    const existing = await getCredProfile(db, `/${slug}`)
    if (existing && !isAncestorOrEqual(tokenPath, existing.path)) {
      return c.json({ error: `Token cannot update profile '${slug}'` }, 403)
    }

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

credProfileRoutes.delete('/:slug', requireToken, requireRight('manage_services'),
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
    const db = c.get('db')
    const slug = c.req.param('slug')
    const existing = await getCredProfile(db, `/${slug}`)
    if (!existing) return c.json({ error: 'Profile not found' }, 404)

    // Admin check: must be at or above the profile's path
    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') as { orgId?: string | null })
    if (!isAncestorOrEqual(tokenPath, existing.path)) {
      return c.json({ error: `Token cannot delete profile '${slug}'` }, 403)
    }

    const deleted = await deleteCredProfile(db, `/${slug}`)
    if (!deleted) return c.json({ error: 'Profile not found' }, 404)
    return c.json({ ok: true as const })
  },
)
