import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import type { AuthScheme } from '../auth-schemes'
import { requireToken, requireRight } from '../core/middleware'
import {
  extractGrants,
  getPublicKeyHex,
} from '../biscuit'
import {
  listServices,
  getService,
  upsertService,
  deleteService,
} from '../db/queries'
import { encryptSecret } from '../lib/credentials-crypto'
import { RESERVED_PATHS, deriveDisplayName } from '../lib/utils'

export const serviceRoutes = new Hono<CoreHonoEnv>()

serviceRoutes.get('/', requireToken, async c => {
  const db = c.get('db')
  const allServices = await listServices(db)

  const mgmt = c.get('managementRights')!
  if (mgmt.rights.includes('manage_services')) {
    return c.json(
      allServices.map(s => ({
        service: s.service,
        baseUrl: s.baseUrl,
        description: s.description,
        docsUrl: s.docsUrl,
      })),
    )
  }

  const token = c.get('token')!
  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
  const grants = extractGrants(token, publicKeyHex)
  const allowedServices = new Set<string>()
  for (const grant of grants) {
    for (const svc of grant.services) {
      if (svc === '*') {
        for (const s of allServices) allowedServices.add(s.service)
      } else {
        allowedServices.add(svc)
      }
    }
  }

  return c.json(
    allServices
      .filter(s => allowedServices.has(s.service))
      .map(s => ({
        service: s.service,
        baseUrl: s.baseUrl,
        description: s.description,
        docsUrl: s.docsUrl,
      })),
  )
})

serviceRoutes.get('/:service', requireToken, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')

  // Check authorization: manage_services right or a grant for this service
  const mgmt = c.get('managementRights')!
  let authorized = mgmt.rights.includes('manage_services')

  if (!authorized) {
    const token = c.get('token')!
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const grants = extractGrants(token, publicKeyHex)
    for (const grant of grants) {
      if (grant.services.includes('*') || grant.services.includes(serviceName)) {
        authorized = true
        break
      }
    }
  }

  if (!authorized) return c.json({ error: 'Forbidden' }, 403)

  const service = await getService(db, serviceName)
  if (!service) return c.json({ error: 'Service not found' }, 404)

  return c.json({
    service: service.service,
    baseUrl: service.baseUrl,
    displayName: service.displayName,
    description: service.description,
    docsUrl: service.docsUrl,
    authSchemes: service.authSchemes ? JSON.parse(service.authSchemes) : null,
  })
})

serviceRoutes.put('/:service', requireToken, requireRight('manage_services'), async c => {
  const service = c.req.param('service')
  if (RESERVED_PATHS.has(service)) {
    return c.json({ error: `'${service}' is a reserved name` }, 400)
  }

  const body = await c.req.json<{
    baseUrl: string
    authSchemes?: AuthScheme[]
    displayName?: string
    description?: string
    oauthClientId?: string
    oauthClientSecret?: string
    docsUrl?: string
    authConfig?: Record<string, unknown>
  }>()

  if (!body.baseUrl) return c.json({ error: 'baseUrl is required' }, 400)

  const db = c.get('db')
  const displayName = body.displayName ?? deriveDisplayName(service)

  await upsertService(db, service, {
    baseUrl: body.baseUrl,
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

  return c.json({ ok: true, service })
})

serviceRoutes.delete('/:service', requireToken, requireRight('manage_services'), async c => {
  const db = c.get('db')
  const deleted = await deleteService(db, c.req.param('service'))
  if (!deleted) return c.json({ error: 'Service not found' }, 404)
  return c.json({ ok: true })
})
