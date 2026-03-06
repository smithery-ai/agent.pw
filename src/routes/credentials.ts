import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken, resolveUserId } from '../core/middleware'
import {
  getService,
  listCredentials,
  upsertCredential,
  deleteCredential,
} from '../db/queries'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'

export const CredentialSchema = z.object({
  slug: z.string().meta({ description: 'Service slug', example: 'linear' }),
  label: z.string().meta({ description: 'Credential label', example: 'default' }),
  createdAt: z.string().meta({ description: 'ISO 8601 creation timestamp' }),
}).meta({ id: 'Credential' })

export const CreateCredentialRequestSchema = z.object({
  token: z.string().optional().meta({ description: 'API token or secret' }),
  headers: z.record(z.string(), z.string()).optional().meta({ description: 'Explicit header map to send on proxied requests' }),
  label: z.string().optional().meta({ description: 'Credential label (defaults to "default")', example: 'default' }),
}).meta({ id: 'CreateCredentialRequest' })

export const credentialRoutes = new Hono<CoreHonoEnv>()

credentialRoutes.get('/', requireToken, resolveUserId,
  describeRoute({
    tags: ['credentials'],
    summary: 'List credentials',
    description: 'List all credentials for the authenticated user.',
    responses: {
      200: { description: 'List of credentials', content: { 'application/json': { schema: resolver(z.array(CredentialSchema)) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const userId = c.get('userId') as string
    const creds = await listCredentials(db, userId)
    return c.json(
      creds.map(cr => ({
        slug: cr.slug,
        label: cr.label,
        createdAt: cr.createdAt,
      })),
    )
  },
)

credentialRoutes.put('/:slug', requireToken, resolveUserId,
  describeRoute({
    tags: ['credentials'],
    summary: 'Store credential',
    description: 'Create or update a credential for a service. Provide either a token or explicit headers.',
    responses: {
      200: { description: 'Credential stored', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true), user: z.string(), slug: z.string() }).meta({ id: 'CredentialStored' })) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'CredentialError' })) } } },
      404: { description: 'Service not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('json', CreateCredentialRequestSchema),
  async c => {
    const userId = c.get('userId') as string
    const slug = c.req.param('slug')
    const body = c.req.valid('json')
    if (!body.token && !body.headers) {
      return c.json({ error: 'Either token or headers is required' }, 400)
    }

    const db = c.get('db')
    const svc = await getService(db, slug)
    if (!svc) return c.json({ error: `Service '${slug}' not configured` }, 404)

    const schemes = parseAuthSchemes(svc.authSchemes)
    const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
    const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token as string)
    const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

    await upsertCredential(db, userId, slug, body.label ?? 'default', encrypted)
    return c.json({ ok: true as const, user: userId, slug })
  },
)

credentialRoutes.delete('/:slug', requireToken, resolveUserId,
  describeRoute({
    tags: ['credentials'],
    summary: 'Delete credential',
    description: 'Delete a credential by service slug and optional label.',
    responses: {
      200: { description: 'Credential deleted', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true) })) } } },
      404: { description: 'Credential not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const userId = c.get('userId') as string
    const label = c.req.query('label') ?? 'default'
    const deleted = await deleteCredential(db, userId, c.req.param('slug'), label)
    if (!deleted) return c.json({ error: 'Credential not found' }, 404)
    return c.json({ ok: true as const })
  },
)
