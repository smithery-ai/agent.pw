import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import {
  getCredProfile,
  getCredential,
  listCredentialsAccessible,
  upsertCredential,
  deleteCredential,
} from '../db/queries'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'
import {
  credentialName,
  credentialParentPath,
  joinCredentialPath,
  pathFromTokenFacts,
  isAncestorOrEqual,
  validateCredentialName,
  validatePath,
} from '../paths'

export const CredentialSchema = z.object({
  name: z.string().meta({ description: 'Credential name', example: 'linear' }),
  host: z.string().meta({ description: 'Target hostname', example: 'api.linear.app' }),
  path: z.string().meta({ description: 'Full credential path', example: '/orgs/ruzo/linear' }),
  createdAt: z.string().meta({ description: 'ISO 8601 creation timestamp' }),
}).meta({ id: 'Credential' })

export const CreateCredentialRequestSchema = z.object({
  token: z.string().optional().meta({ description: 'API token or secret' }),
  headers: z.record(z.string(), z.string()).optional().meta({ description: 'Explicit header map to send on proxied requests' }),
  host: z.string().optional().meta({ description: 'Target hostname for this credential', example: 'api.linear.app' }),
  profile: z.string().optional().meta({ description: 'Credential profile slug to derive the target host from', example: 'linear' }),
  path: z.string().optional().meta({ description: 'Full credential path (defaults to token path + name)', example: '/orgs/ruzo/linear' }),
}).meta({ id: 'CreateCredentialRequest' })

export const credentialRoutes = new Hono<CoreHonoEnv>()

credentialRoutes.get('/', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'List credentials',
    description: 'List all credentials accessible to this token (owned + inherited).',
    responses: {
      200: { description: 'List of credentials', content: { 'application/json': { schema: resolver(z.array(CredentialSchema)) } } },
    },
  }),
  async c => {
    const db = c.get('db')
    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') ?? {})
    const creds = await listCredentialsAccessible(db, tokenPath)
    return c.json(
      creds.map(cr => ({
        name: credentialName(cr.path),
        host: cr.host,
        path: cr.path,
        createdAt: cr.createdAt,
      })),
    )
  },
)

credentialRoutes.put('/:name', requireToken,
  describeRoute({
    tags: ['credentials'],
    summary: 'Store credential',
    description: 'Create or update a credential for a service. Provide either a token or explicit headers.',
    responses: {
      200: { description: 'Credential stored', content: { 'application/json': { schema: resolver(z.object({ ok: z.literal(true), name: z.string(), path: z.string() }).meta({ id: 'CredentialStored' })) } } },
      400: { description: 'Invalid request', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'CredentialError' })) } } },
      404: { description: 'Profile not found', content: { 'application/json': { schema: resolver(z.object({ error: z.string() })) } } },
    },
  }),
  zValidator('json', CreateCredentialRequestSchema),
  async c => {
    const name = c.req.param('name')
    if (!validateCredentialName(name)) {
      return c.json({ error: 'Invalid credential name' }, 400)
    }

    const body = c.req.valid('json')
    if (!body.token && !body.headers) {
      return c.json({ error: 'Either token or headers is required' }, 400)
    }

    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') ?? {})
    const credPath = body.path ?? joinCredentialPath(tokenPath, name)

    if (!validatePath(credPath) || credPath === '/') {
      return c.json({ error: 'Invalid path' }, 400)
    }
    if (credentialName(credPath) !== name) {
      return c.json({ error: 'Credential path must end with the route name' }, 400)
    }

    // Creation/update: token can only create at its own path or deeper
    if (!isAncestorOrEqual(tokenPath, credentialParentPath(credPath))) {
      return c.json({ error: 'Cannot create credentials above your path' }, 403)
    }

    const db = c.get('db')
    const profileSlug = '/' + (body.profile ?? name)
    const profile = body.host ? null : await getCredProfile(db, profileSlug)
    if (!body.host && !profile) {
      return c.json({ error: `Profile '${profileSlug}' not configured` }, 404)
    }

    const host = body.host ?? profile?.host[0]
    if (!host) return c.json({ error: 'host is required when no profile host can be resolved' }, 400)

    const authConfig = profile?.auth ?? null
    const schemes = authConfig?.kind === 'oauth' ? [] : parseAuthSchemes(authConfig?.authSchemes ? JSON.stringify(authConfig.authSchemes) : null)
    const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
    const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token as string)
    const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

    const existing = await getCredential(db, host, credPath)
    if (existing && !isAncestorOrEqual(tokenPath, credentialParentPath(existing.path))) {
      return c.json({ error: `Token cannot update credential '${name}'` }, 403)
    }

    await upsertCredential(db, {
      host,
      path: credPath,
      auth: { kind: 'headers' },
      secret: encrypted,
    })
    return c.json({ ok: true as const, name, path: credPath })
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
  async c => {
    const db = c.get('db')
    const name = c.req.param('name')
    if (!validateCredentialName(name)) {
      return c.json({ error: 'Invalid credential name' }, 400)
    }

    const tokenPath = pathFromTokenFacts(c.get('tokenFacts') ?? {})
    const requestedPath = c.req.query('path') ?? joinCredentialPath(tokenPath, name)
    if (!validatePath(requestedPath) || requestedPath === '/') {
      return c.json({ error: 'Invalid path' }, 400)
    }
    if (credentialName(requestedPath) !== name) {
      return c.json({ error: 'Credential path must end with the route name' }, 400)
    }

    const queryHost = c.req.query('host')
    const queryProfile = c.req.query('profile')
    let host = queryHost ?? null
    if (!host && queryProfile) {
      const profile = await getCredProfile(db, '/' + queryProfile)
      if (!profile) return c.json({ error: `Profile '${queryProfile}' not configured` }, 404)
      host = profile.host[0] ?? null
    }
    if (!host) {
      return c.json({ error: 'host or profile is required' }, 400)
    }

    const existing = await getCredential(db, host, requestedPath)
    if (!existing) return c.json({ error: 'Credential not found' }, 404)

    // Admin check: token must be at or above the credential's path
    if (!isAncestorOrEqual(tokenPath, credentialParentPath(existing.path))) {
      return c.json({ error: `Token cannot delete credential '${name}'` }, 403)
    }

    const deleted = await deleteCredential(db, host, requestedPath)
    if (!deleted) return c.json({ error: 'Credential not found' }, 404)
    return c.json({ ok: true as const })
  },
)
