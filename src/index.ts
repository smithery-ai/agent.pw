import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Env, ProxyConstraint } from './types'
import { encrypt, decrypt } from './crypto'
import {
  mintToken,
  restrictToken,
  authorizeRequest,
  extractGrants,
  extractIdentityFromToken,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
  stripPrefix,
} from './biscuit'
import {
  getService,
  listServices,
  upsertService,
  deleteService,
  getCredential,
  upsertCredential,
  deleteCredential,
  isRevoked,
  revokeToken,
} from './db'

type HonoEnv = { Bindings: Env }

/** Serialize WASM errors (which are not Error instances) */
function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try { return JSON.stringify(e) } catch { return String(e) }
}

const app = new Hono<HonoEnv>()

app.use('*', cors())

// ─── Health ──────────────────────────────────────────────────────────────────

app.get('/', c => c.json({ status: 'ok', service: 'auth-proxy' }))

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getNamespace(env: Env): string {
  return env.NAMESPACE || 'default'
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null
  return header.startsWith('Bearer ') ? header.slice(7) : header
}

function isAdminKey(token: string, env: Env): boolean {
  return token === env.ADMIN_KEY
}

// ─── Admin Middleware ────────────────────────────────────────────────────────

const admin = new Hono<HonoEnv>()

admin.use('*', async (c, next) => {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)
  if (!c.env.ADMIN_KEY) return c.json({ error: 'ADMIN_KEY not configured' }, 500)
  if (!isAdminKey(token, c.env)) return c.json({ error: 'Invalid admin key' }, 403)
  return next()
})

// ─── Admin: Service Management ───────────────────────────────────────────────

admin.get('/services', async c => {
  const ns = getNamespace(c.env)
  const services = await listServices(c.env.DB, ns)
  return c.json(
    services.map(s => ({
      service: s.service,
      baseUrl: s.base_url,
      authMethod: s.auth_method,
      description: s.description,
      specUrl: s.spec_url,
    }))
  )
})

admin.put('/services/:service', async c => {
  const ns = getNamespace(c.env)
  const service = c.req.param('service')
  const body = await c.req.json<{
    baseUrl: string
    authMethod?: string
    headerName?: string
    headerScheme?: string
    description?: string
    specUrl?: string
    authConfig?: Record<string, unknown>
  }>()

  if (!body.baseUrl) return c.json({ error: 'baseUrl is required' }, 400)

  await upsertService(c.env.DB, ns, service, {
    base_url: body.baseUrl,
    auth_method: body.authMethod,
    header_name: body.headerName,
    header_scheme: body.headerScheme,
    description: body.description,
    spec_url: body.specUrl,
    auth_config: body.authConfig ? JSON.stringify(body.authConfig) : undefined,
  })

  return c.json({ ok: true, service })
})

admin.delete('/services/:service', async c => {
  const ns = getNamespace(c.env)
  const deleted = await deleteService(c.env.DB, ns, c.req.param('service'))
  if (!deleted) return c.json({ error: 'Service not found' }, 404)
  return c.json({ ok: true })
})

// ─── Admin: Credential Management ────────────────────────────────────────────

admin.put('/credentials/:service', async c => {
  const ns = getNamespace(c.env)
  const service = c.req.param('service')
  const body = await c.req.json<{
    identity: string
    token: string
    metadata?: Record<string, string>
    expiresAt?: string
  }>()

  if (!body.identity) return c.json({ error: 'identity is required' }, 400)
  if (!body.token) return c.json({ error: 'token is required' }, 400)

  const svc = await getService(c.env.DB, ns, service)
  if (!svc) return c.json({ error: `Service '${service}' not configured. Register it first.` }, 404)

  const { encrypted, iv } = await encrypt(body.token, c.env.ENCRYPTION_KEY)
  await upsertCredential(c.env.DB, ns, service, body.identity, encrypted, iv, body.metadata, body.expiresAt)

  return c.json({ ok: true, service, identity: body.identity })
})

admin.delete('/credentials/:service/:identity', async c => {
  const ns = getNamespace(c.env)
  const deleted = await deleteCredential(c.env.DB, ns, c.req.param('service'), c.req.param('identity'))
  if (!deleted) return c.json({ error: 'Credential not found' }, 404)
  return c.json({ ok: true })
})

// ─── Admin: Token Management ─────────────────────────────────────────────────

admin.post('/tokens/mint', async c => {
  const body = await c.req.json<{ grants: ProxyConstraint[] }>()

  if (!body.grants || !Array.isArray(body.grants) || body.grants.length === 0) {
    return c.json({ error: 'grants array is required' }, 400)
  }

  try {
    const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, body.grants)
    const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    return c.json({ token, publicKey })
  } catch (e) {
    return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
  }
})

admin.post('/tokens/revoke', async c => {
  const body = await c.req.json<{ token: string; reason?: string }>()
  if (!body.token) return c.json({ error: 'token is required' }, 400)

  try {
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(body.token, publicKeyHex)

    for (const id of revIds) {
      await revokeToken(c.env.DB, id, body.reason)
    }

    return c.json({ ok: true, revokedIds: revIds })
  } catch (e) {
    return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
  }
})

admin.post('/keys/generate', async c => {
  return c.json(generateKeyPairHex())
})

app.route('/admin', admin)

// ─── Token Restriction (public - anyone with a token can restrict it) ────────

app.post('/tokens/restrict', async c => {
  const body = await c.req.json<{ token: string; constraints: ProxyConstraint[] }>()
  if (!body.token) return c.json({ error: 'token is required' }, 400)
  if (!body.constraints || body.constraints.length === 0) {
    return c.json({ error: 'constraints array is required' }, 400)
  }

  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

  try {
    const restricted = restrictToken(body.token, publicKeyHex, body.constraints)
    return c.json({ token: restricted })
  } catch (e) {
    return c.json({ error: `Failed to restrict token: ${errorMessage(e)}` }, 400)
  }
})

// ─── Discoverability (scoped by token) ───────────────────────────────────────

app.get('/services', async c => {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const ns = getNamespace(c.env)
  const allServices = await listServices(c.env.DB, ns)

  // Admin key: return all services
  if (isAdminKey(token, c.env)) {
    return c.json(
      allServices.map(s => ({
        service: s.service,
        baseUrl: s.base_url,
        description: s.description,
        specUrl: s.spec_url,
      }))
    )
  }

  // Scoped token: filter by what the token allows
  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
  const grants = extractGrants(token, publicKeyHex)

  const allowedServices = new Set<string>()
  const serviceGrants = new Map<string, { methods: string[]; paths: string[] }>()

  for (const grant of grants) {
    for (const svc of grant.services) {
      if (svc === '*') {
        for (const s of allServices) {
          allowedServices.add(s.service)
          if (!serviceGrants.has(s.service)) {
            serviceGrants.set(s.service, { methods: grant.methods, paths: grant.paths })
          }
        }
      } else {
        allowedServices.add(svc)
        if (!serviceGrants.has(svc)) {
          serviceGrants.set(svc, { methods: grant.methods, paths: grant.paths })
        }
      }
    }
  }

  return c.json(
    allServices
      .filter(s => allowedServices.has(s.service))
      .map(s => {
        const grantInfo = serviceGrants.get(s.service)
        return {
          service: s.service,
          baseUrl: s.base_url,
          description: s.description,
          specUrl: s.spec_url,
          allowedMethods: grantInfo?.methods?.filter(m => m !== '*'),
          allowedPaths: grantInfo?.paths?.filter(p => p !== '*'),
        }
      })
  )
})

// ─── Authenticated Proxy ────────────────────────────────────────────────────

app.all('/proxy/:service/*', async c => {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const service = c.req.param('service')
  const ns = getNamespace(c.env)

  // Get upstream path (everything after /proxy/{service})
  const url = new URL(c.req.url)
  const proxyPrefix = `/proxy/${service}`
  const upstreamPath = url.pathname.slice(proxyPrefix.length) || '/'

  // Look up service config
  const svc = await getService(c.env.DB, ns, service)
  if (!svc) return c.json({ error: `Unknown service: ${service}` }, 404)

  let identity: string

  if (isAdminKey(token, c.env)) {
    // Admin key: full access, use default identity
    identity = 'default'
  } else {
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

    // Check revocation
    try {
      const revIds = getRevocationIds(token, publicKeyHex)
      for (const id of revIds) {
        if (await isRevoked(c.env.DB, id)) {
          return c.json({ error: 'Token has been revoked' }, 403)
        }
      }
    } catch (e) {
      return c.json({ error: `Invalid token: ${errorMessage(e)}` }, 401)
    }

    // Authorize
    const result = authorizeRequest(token, publicKeyHex, service, c.req.method, upstreamPath)
    if (!result.authorized) {
      return c.json({ error: 'Forbidden', details: result.error }, 403)
    }

    // Extract identity from token metadata
    identity = extractIdentityFromToken(token, publicKeyHex, service) ?? 'default'
  }

  // Look up credential
  const cred = await getCredential(c.env.DB, ns, service, identity)
  if (!cred) {
    return c.json({ error: `No credential found for ${service}/${identity}` }, 404)
  }

  // Decrypt credential
  const decryptedToken = await decrypt(cred.encrypted, cred.iv, c.env.ENCRYPTION_KEY)

  // Build upstream request
  const upstreamUrl = `${svc.base_url.replace(/\/$/, '')}${upstreamPath}${url.search}`

  const headers = new Headers()
  for (const [key, value] of c.req.raw.headers.entries()) {
    if (key.toLowerCase() === 'authorization') continue
    if (key.toLowerCase() === 'host') continue
    headers.set(key, value)
  }

  // Inject credential
  if (svc.auth_method === 'bearer' || svc.auth_method === 'oauth2') {
    headers.set(svc.header_name, `${svc.header_scheme} ${decryptedToken}`)
  } else if (svc.auth_method === 'api_key') {
    headers.set(svc.header_name, decryptedToken)
  } else if (svc.auth_method === 'basic') {
    headers.set(svc.header_name, `Basic ${btoa(decryptedToken)}`)
  }

  // Forward request
  const body = ['GET', 'HEAD'].includes(c.req.method) ? undefined : await c.req.raw.arrayBuffer()

  const upstream = await fetch(upstreamUrl, {
    method: c.req.method,
    headers,
    body,
  })

  // Return response transparently
  const responseHeaders = new Headers(upstream.headers)
  responseHeaders.delete('transfer-encoding')

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  })
})

export default app
