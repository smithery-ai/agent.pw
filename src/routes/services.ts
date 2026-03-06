import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import type { AuthScheme } from '../auth-schemes'
import { requireToken, requireRight } from '../core/middleware'
import {
  listServices,
  getService,
  upsertService,
  deleteService,
} from '../db/queries'
import { encryptSecret } from '../lib/credentials-crypto'
import { RESERVED_PATHS } from '../lib/utils'

export const serviceRoutes = new Hono<CoreHonoEnv>()

serviceRoutes.get('/', requireToken, async c => {
  const db = c.get('db')
  const allServices = await listServices(db)

  return c.json(
    allServices.map(s => ({
      slug: s.slug,
      allowedHosts: JSON.parse(s.allowedHosts) as string[],
      displayName: s.displayName,
      description: s.description,
      docsUrl: s.docsUrl,
    })),
  )
})

serviceRoutes.get('/:slug', requireToken, async c => {
  const slug = c.req.param('slug')
  const db = c.get('db')

  const service = await getService(db, slug)
  if (!service) return c.json({ error: 'Service not found' }, 404)

  return c.json({
    slug: service.slug,
    allowedHosts: JSON.parse(service.allowedHosts) as string[],
    displayName: service.displayName,
    description: service.description,
    docsUrl: service.docsUrl,
    authSchemes: service.authSchemes ? JSON.parse(service.authSchemes) : null,
  })
})

serviceRoutes.put('/:slug', requireToken, requireRight('manage_services'), async c => {
  const slug = c.req.param('slug')
  if (RESERVED_PATHS.has(slug)) {
    return c.json({ error: `'${slug}' is a reserved name` }, 400)
  }

  const body = await c.req.json<{
    allowedHosts: string[]
    authSchemes?: AuthScheme[]
    displayName?: string
    description?: string
    oauthClientId?: string
    oauthClientSecret?: string
    docsUrl?: string
    authConfig?: Record<string, unknown>
  }>()

  if (!body.allowedHosts || body.allowedHosts.length === 0) {
    return c.json({ error: 'allowedHosts is required' }, 400)
  }

  const db = c.get('db')
  const displayName = body.displayName ?? slug.charAt(0).toUpperCase() + slug.slice(1)

  await upsertService(db, slug, {
    allowedHosts: JSON.stringify(body.allowedHosts),
    authSchemes: body.authSchemes ? JSON.stringify(body.authSchemes) : undefined,
    displayName,
    description: body.description,
    oauthClientId: body.oauthClientId,
    encryptedOauthClientSecret: body.oauthClientSecret
      ? await encryptSecret(c.env.ENCRYPTION_KEY, body.oauthClientSecret)
      : undefined,
    docsUrl: body.docsUrl,
    authConfig: body.authConfig ? JSON.stringify(body.authConfig) : undefined,
  })

  return c.json({ ok: true, slug })
})

serviceRoutes.delete('/:slug', requireToken, requireRight('manage_services'), async c => {
  const db = c.get('db')
  const deleted = await deleteService(db, c.req.param('slug'))
  if (!deleted) return c.json({ error: 'Service not found' }, 404)
  return c.json({ ok: true })
})
