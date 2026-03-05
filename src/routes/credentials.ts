import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import { requireToken, resolveOrgId } from '../core/middleware'
import {
  getService,
  listCredentials,
  upsertCredential,
  deleteCredential,
} from '../db/queries'
import { getKnownOAuthProvider } from '../oauth-providers'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'

export const credentialRoutes = new Hono<CoreHonoEnv>()

credentialRoutes.get('/', requireToken, resolveOrgId, async c => {
  const db = c.get('db')
  const orgId = c.get('orgId')!
  const creds = await listCredentials(db, orgId)
  return c.json(
    creds.map(cr => ({
      service: cr.service,
      slug: cr.slug,
      createdAt: cr.createdAt,
    })),
  )
})

credentialRoutes.put('/:service', requireToken, resolveOrgId, async c => {
  const orgId = c.get('orgId')!
  const service = c.req.param('service')
  const body = await c.req.json<{
    token?: string
    headers?: Record<string, string>
    slug?: string
  }>()
  if (!body.token && !body.headers) {
    return c.json({ error: 'Either token or headers is required' }, 400)
  }

  const db = c.get('db')
  const svc = await getService(db, service)
  if (!svc) return c.json({ error: `Service '${service}' not configured` }, 404)

  // Build headers: use explicit map or derive from token + service config
  // Prefer known provider's scheme over DB (fixes stale migration data)
  const knownProvider = getKnownOAuthProvider(service)
  const schemes = knownProvider ? knownProvider.authSchemes : parseAuthSchemes(svc.authSchemes)
  const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
  const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token!)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

  await upsertCredential(db, orgId, service, body.slug ?? 'default', encrypted)
  return c.json({ ok: true, org: orgId, service })
})

credentialRoutes.delete('/:service', requireToken, resolveOrgId, async c => {
  const db = c.get('db')
  const orgId = c.get('orgId')!
  const credSlug = c.req.query('slug') ?? 'default'
  const deleted = await deleteCredential(db, orgId, c.req.param('service'), credSlug)
  if (!deleted) return c.json({ error: 'Credential not found' }, 404)
  return c.json({ ok: true })
})
