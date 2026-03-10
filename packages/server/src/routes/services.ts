import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { AuthScheme } from '../auth-schemes'
import { requireToken, requireRight } from '../core/middleware'
import {
  listServices,
  getService,
  upsertService,
  deleteService,
} from '../db/queries'
import { encryptSecret } from '../lib/credentials-crypto'
import { RESERVED_PATHS } from '../lib/utils'
import {
  buildListPageSchema,
  InvalidPaginationCursorError,
  paginateItems,
  PaginationQuerySchema,
} from '../lib/pagination'

export const ServiceSchema = z.object({
  slug: z.string().meta({ description: 'Unique service identifier', example: 'linear' }),
  allowedHosts: z.array(z.string()).meta({ description: 'Hostnames the proxy may forward to', example: ['api.linear.app'] }),
  displayName: z.string().nullable().meta({ description: 'Human-readable display name' }),
  description: z.string().nullable().meta({ description: 'Service description' }),
  docsUrl: z.string().nullable().meta({ description: 'Link to API documentation' }),
}).meta({ id: 'Service' })

export const ServiceDetailSchema = ServiceSchema.extend({
  authSchemes: z.array(AuthScheme).nullable().meta({ description: 'Supported authentication schemes' }),
}).meta({ id: 'ServiceDetail' })

export const ServiceListPageSchema = buildListPageSchema(ServiceSchema, 'ServiceListPage')

export const CreateServiceRequestSchema = z.object({
  allowedHosts: z.array(z.string()).min(1).meta({ description: 'Hostnames the proxy may forward to' }),
  authSchemes: z.array(AuthScheme).optional().meta({ description: 'Supported authentication schemes' }),
  displayName: z.string().optional().meta({ description: 'Human-readable display name' }),
  description: z.string().optional().meta({ description: 'Service description' }),
  oauthClientId: z.string().optional().meta({ description: 'OAuth2 client ID' }),
  oauthClientSecret: z.string().optional().meta({ description: 'OAuth2 client secret (stored encrypted)' }),
  docsUrl: z.string().optional().meta({ description: 'Link to API documentation' }),
  authConfig: z.record(z.string(), z.unknown()).optional().meta({ description: 'Additional auth configuration' }),
}).meta({ id: 'CreateServiceRequest' })

export const ErrorSchema = z.object({
  error: z.string().meta({ example: 'Service not found' }),
}).meta({ id: 'Error' })

export const OkSchema = z.object({
  ok: z.literal(true),
}).meta({ id: 'Ok' })

export const OkWithSlugSchema = OkSchema.extend({
  slug: z.string(),
}).meta({ id: 'OkWithSlug' })

export const serviceRoutes = new Hono<CoreHonoEnv>()

serviceRoutes.get('/', requireToken,
  describeRoute({
    tags: ['services'],
    summary: 'List services',
    description: 'List configured services with cursor-based pagination.',
    responses: {
      200: { description: 'Paginated list of services', content: { 'application/json': { schema: resolver(ServiceListPageSchema) } } },
      400: { description: 'Invalid pagination cursor', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  zValidator('query', PaginationQuerySchema),
  async c => {
    const db = c.get('db')
    const query = c.req.valid('query')
    const allServices = (await listServices(db))
      .map(s => ({
        slug: s.slug,
        allowedHosts: JSON.parse(s.allowedHosts) as string[],
        displayName: s.displayName,
        description: s.description,
        docsUrl: s.docsUrl,
      }))
      .sort((a, b) => a.slug.localeCompare(b.slug))

    try {
      return c.json(paginateItems({
        items: allServices,
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

serviceRoutes.get('/:slug', requireToken,
  describeRoute({
    tags: ['services'],
    summary: 'Get service',
    description: 'Get a service by slug, including its auth schemes.',
    responses: {
      200: { description: 'Service details', content: { 'application/json': { schema: resolver(ServiceDetailSchema) } } },
      404: { description: 'Service not found', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  async c => {
    const slug = c.req.param('slug')
    const db = c.get('db')

    const service = await getService(db, `/${slug}`)
    if (!service) return c.json({ error: 'Service not found' }, 404)

    return c.json({
      slug: service.slug,
      allowedHosts: JSON.parse(service.allowedHosts) as string[],
      displayName: service.displayName,
      description: service.description,
      docsUrl: service.docsUrl,
      authSchemes: service.authSchemes ? JSON.parse(service.authSchemes) : null,
    })
  },
)

serviceRoutes.put('/:slug', requireToken, requireRight('manage_services'),
  describeRoute({
    tags: ['services'],
    summary: 'Create or update service',
    description: 'Register a new service or update an existing one by slug.',
    responses: {
      200: { description: 'Service created or updated', content: { 'application/json': { schema: resolver(OkWithSlugSchema) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  zValidator('json', CreateServiceRequestSchema),
  async c => {
    const slug = c.req.param('slug')
    if (RESERVED_PATHS.has(slug)) {
      return c.json({ error: `'${slug}' is a reserved name` }, 400)
    }

    const body = c.req.valid('json')

    const db = c.get('db')
    const displayName = body.displayName ?? slug.charAt(0).toUpperCase() + slug.slice(1)

    await upsertService(db, `/${slug}`, {
      allowedHosts: body.allowedHosts,
      authSchemes: body.authSchemes,
      displayName,
      description: body.description,
      oauthClientId: body.oauthClientId,
      encryptedOauthClientSecret: body.oauthClientSecret
        ? await encryptSecret(c.env.ENCRYPTION_KEY, body.oauthClientSecret)
        : undefined,
      docsUrl: body.docsUrl,
      authConfig: body.authConfig,
    })

    return c.json({ ok: true as const, slug })
  },
)

serviceRoutes.delete('/:slug', requireToken, requireRight('manage_services'),
  describeRoute({
    tags: ['services'],
    summary: 'Delete service',
    description: 'Remove a service by slug.',
    responses: {
      200: { description: 'Service deleted', content: { 'application/json': { schema: resolver(OkSchema) } } },
      404: { description: 'Service not found', content: { 'application/json': { schema: resolver(ErrorSchema) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const deleted = await deleteService(db, `/${c.req.param('slug')}`)
    if (!deleted) return c.json({ error: 'Service not found' }, 404)
    return c.json({ ok: true as const })
  },
)
