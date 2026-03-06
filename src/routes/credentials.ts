import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import {
  getCredProfile,
  listCredentials,
  upsertCredential,
  deleteCredential,
} from '../db/queries'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'
import { randomId } from '../lib/utils'

export const CredentialSchema = z.object({
  slug: z.string().meta({ description: 'Credential slug', example: 'linear' }),
  host: z.string().meta({ description: 'Target hostname', example: 'api.linear.app' }),
  createdAt: z.string().meta({ description: 'ISO 8601 creation timestamp' }),
}).meta({ id: 'Credential' })

export const CreateCredentialRequestSchema = z.object({
  token: z.string().optional().meta({ description: 'API token or secret' }),
  headers: z.record(z.string(), z.string()).optional().meta({ description: 'Explicit header map to send on proxied requests' }),
  host: z.string().optional().meta({ description: 'Target hostname for this credential', example: 'api.linear.app' }),
  profile: z.string().optional().meta({ description: 'Credential profile slug to derive the target host from', example: 'linear' }),
}).meta({ id: 'CreateCredentialRequest' })

export const credentialRoutes = new Hono<CoreHonoEnv>()

credentialRoutes.get('/', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'List credentials',
    description: 'List all credentials.',
    responses: {
      200: { description: 'List of credentials', content: { 'application/json': { schema: resolver(z.array(CredentialSchema)) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const creds = await listCredentials(db)
    return c.json(
      creds.map(cr => ({
        slug: cr.slug,
        host: cr.host,
        createdAt: cr.createdAt,
      })),
    )
  },
)

credentialRoutes.put('/:slug', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Store credential',
    description: 'Create or update a credential for a service. Provide either a token or explicit headers.',
    responses: {
      200: { description: 'Credential stored', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true), slug: z.string() }).meta({ id: 'CredentialStored' })) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'CredentialError' })) } } },
      404: { description: 'Profile not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('json', CreateCredentialRequestSchema),
  async c => {
    const slug = c.req.param('slug')
    const body = c.req.valid('json')
    if (!body.token && !body.headers) {
      return c.json({ error: 'Either token or headers is required' }, 400)
    }

    const db = c.get('db')
    const profileSlug = body.profile ?? slug
    const profile = body.host ? null : await getCredProfile(db, profileSlug)
    if (!body.host && !profile) {
      return c.json({ error: `Profile '${profileSlug}' not configured` }, 404)
    }

    const host = body.host ?? (() => {
      const hosts: string[] = profile ? JSON.parse(profile.host) : []
      return hosts[0]
    })()
    if (!host) return c.json({ error: 'host is required when no profile host can be resolved' }, 400)

    const authConfig = profile?.auth ? JSON.parse(profile.auth) : null
    const schemes = authConfig?.kind === 'oauth' ? [] : parseAuthSchemes(authConfig?.authSchemes ? JSON.stringify(authConfig.authSchemes) : null)
    const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
    const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token as string)
    const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

    await upsertCredential(db, {
      id: randomId(),
      host,
      slug,
      auth: JSON.stringify({ kind: 'headers' }),
      secret: encrypted,
    })
    return c.json({ ok: true as const, slug })
  },
)

credentialRoutes.delete('/:slug', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Delete credential',
    description: 'Delete a credential by slug.',
    responses: {
      200: { description: 'Credential deleted', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true) })) } } },
      404: { description: 'Credential not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const deleted = await deleteCredential(db, c.req.param('slug'))
    if (!deleted) return c.json({ error: 'Credential not found' }, 404)
    return c.json({ ok: true as const })
  },
)
