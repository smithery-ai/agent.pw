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

export const CredProfileSchema = z.object({
  slug: z.string().meta({ description: 'Unique profile identifier', example: 'linear' }),
  host: z.array(z.string()).meta({ description: 'Hostnames this profile applies to', example: ['api.linear.app'] }),
  displayName: z.string().nullable().meta({ description: 'Human-readable display name' }),
  description: z.string().nullable().meta({ description: 'Profile description' }),
}).meta({ id: 'CredProfile' })

export const CredProfileDetailSchema = CredProfileSchema.extend({
  auth: z.unknown().nullable().meta({ description: 'Auth configuration (OAuth or headers)' }),
}).meta({ id: 'CredProfileDetail' })

export const CreateCredProfileRequestSchema = z.object({
  host: z.array(z.string()).min(1).meta({ description: 'Hostnames this profile applies to' }),
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
    description: 'List all configured credential profiles.',
    responses: {
      200: { description: 'List of profiles', content: { 'application/json': { schema: resolver(z.array(CredProfileSchema)) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const allProfiles = await listCredProfiles(db)

    return c.json(
      allProfiles.map(p => ({
        slug: p.slug,
        host: p.host,
        displayName: p.displayName,
        description: p.description,
      })),
    )
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

    const profile = await getCredProfile(db, slug)
    if (!profile) return c.json({ error: 'Profile not found' }, 404)

    return c.json({
      slug: profile.slug,
      host: profile.host,
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

    if (!body.host || body.host.length === 0) {
      return c.json({ error: 'host is required' }, 400)
    }

    const db = c.get('db')
    const displayName = body.displayName ?? slug.charAt(0).toUpperCase() + slug.slice(1)

    await upsertCredProfile(db, slug, {
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
    const deleted = await deleteCredProfile(db, c.req.param('slug'))
    if (!deleted) return c.json({ error: 'Profile not found' }, 404)
    return c.json({ ok: true as const })
  },
)
