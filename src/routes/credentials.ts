import { Hono } from 'hono'
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

export const credentialRoutes = new Hono<CoreHonoEnv>()

credentialRoutes.get('/', requireToken, resolveUserId, async c => {
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
})

credentialRoutes.put('/:slug', requireToken, resolveUserId, async c => {
  const userId = c.get('userId') as string
  const slug = c.req.param('slug')
  const body = await c.req.json<{
    token?: string
    headers?: Record<string, string>
    label?: string
  }>()
  if (!body.token && !body.headers) {
    return c.json({ error: 'Either token or headers is required' }, 400)
  }

  const db = c.get('db')
  const svc = await getService(db, slug)
  if (!svc) return c.json({ error: `Service '${slug}' not configured` }, 404)

  // Build headers: use explicit map or derive from token + service auth config
  const schemes = parseAuthSchemes(svc.authSchemes)
  const apiKeyScheme = getApiKeyScheme(schemes) ?? DEFAULT_API_KEY_SCHEME
  const credHeaders = body.headers ?? buildCredentialHeaders(apiKeyScheme, body.token as string)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

  await upsertCredential(db, userId, slug, body.label ?? 'default', encrypted)
  return c.json({ ok: true, user: userId, slug })
})

credentialRoutes.delete('/:slug', requireToken, resolveUserId, async c => {
  const db = c.get('db')
  const userId = c.get('userId') as string
  const label = c.req.query('label') ?? 'default'
  const deleted = await deleteCredential(db, userId, c.req.param('slug'), label)
  if (!deleted) return c.json({ error: 'Credential not found' }, 404)
  return c.json({ ok: true })
})
