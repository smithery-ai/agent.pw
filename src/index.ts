import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { HonoEnv, ProxyConstraint } from './types'
import type { Database } from './db/index'
import {
  mintToken,
  mintManagementToken,
  restrictToken,
  extractGrants,
  extractManagementRights,
  extractVaultFromToken,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
} from './biscuit'
import {
  getService,
  listServices,
  upsertService,
  deleteService,
  getCredential,
  upsertCredential,
  deleteCredential,
  revokeToken,
  getAuthFlow,
  getVault,
  listVaults,
  createVault,
  deleteVault,
  listCredentials,
} from './db/queries'
import { extractBearerToken, handleProxy } from './proxy'
import { requireToken, requireRight, requireVaultAdmin } from './middleware'
import { buildUnauthDiscovery, buildAuthDiscovery, wantsJson } from './discovery'
import { oauthRoutes } from './oauth'
import { apiKeyRoutes } from './api-key'
import { ServiceLandingPage } from './ui'
import { docRoutes } from './discovery/serve'
import { encryptCredentials, buildCredentialHeaders } from './lib/credentials-crypto'

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

const RESERVED_PATHS = new Set(['auth', 'tokens', 'services', 'vaults', 'keys', 'proxy'])

interface AppDeps {
  db: Database
  biscuitPrivateKey: string
  baseUrl: string
  encryptionKey: string
  awsRegion?: string
}

export function createApp(deps: AppDeps) {
  const app = new Hono<HonoEnv>()

  // ─── Global middleware ─────────────────────────────────────────────────────

  app.use('*', cors())

  app.use('*', async (c, next) => {
    if (!c.env) c.env = {} as HonoEnv['Bindings']
    c.env.BISCUIT_PRIVATE_KEY = deps.biscuitPrivateKey
    c.env.BASE_URL = deps.baseUrl
    c.env.ENCRYPTION_KEY = deps.encryptionKey
    c.env.AWS_REGION = deps.awsRegion
    c.set('db', deps.db)
    return next()
  })

  // ─── Health ────────────────────────────────────────────────────────────────

  app.get('/', c => c.json({ status: 'ok', service: 'warden' }))

  // ─── Vault Management ─────────────────────────────────────────────────────

  app.post('/vaults', requireToken, requireRight('manage_vaults'), async c => {
    const body = await c.req.json<{ slug: string; displayName?: string }>()
    if (!body.slug) return c.json({ error: 'slug is required' }, 400)
    const db = c.get('db')
    await createVault(db, body.slug, body.displayName)
    return c.json({ ok: true, slug: body.slug })
  })

  app.get('/vaults', requireToken, async c => {
    const mgmt = c.get('managementRights')!
    const db = c.get('db')
    const allVaults = await listVaults(db)
    if (mgmt.rights.includes('manage_vaults') || mgmt.vaultAdminSlugs.includes('*')) {
      return c.json(allVaults)
    }
    return c.json(allVaults.filter(v => mgmt.vaultAdminSlugs.includes(v.slug)))
  })

  app.delete('/vaults/:slug', requireToken, requireVaultAdmin('slug'), async c => {
    const db = c.get('db')
    const deleted = await deleteVault(db, c.req.param('slug'))
    if (!deleted) return c.json({ error: 'Vault not found' }, 404)
    return c.json({ ok: true })
  })

  // ─── Credential Management (vault-scoped) ─────────────────────────────────

  app.get('/vaults/:slug/credentials', requireToken, requireVaultAdmin('slug'), async c => {
    const db = c.get('db')
    const creds = await listCredentials(db, c.req.param('slug'))
    return c.json(
      creds.map(cr => ({
        service: cr.service,
        identity: cr.identity,
        hasCredentials: !!cr.encryptedCredentials,
        expiresAt: cr.expiresAt,
      })),
    )
  })

  app.put(
    '/vaults/:slug/credentials/:service',
    requireToken,
    requireVaultAdmin('slug'),
    async c => {
      const vaultSlug = c.req.param('slug')
      const service = c.req.param('service')
      const body = await c.req.json<{
        token?: string
        headers?: Record<string, string>
        identity?: string
        metadata?: Record<string, string>
        expiresAt?: string
      }>()
      if (!body.token && !body.headers) {
        return c.json({ error: 'Either token or headers is required' }, 400)
      }

      const db = c.get('db')
      const svc = await getService(db, service)
      if (!svc) return c.json({ error: `Service '${service}' not configured` }, 404)
      const vault = await getVault(db, vaultSlug)
      if (!vault) return c.json({ error: `Vault '${vaultSlug}' not found` }, 404)

      // Build headers: use explicit map or derive from token + service config
      const credHeaders = body.headers ?? buildCredentialHeaders(svc, body.token!)
      const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })

      await upsertCredential(
        db,
        vaultSlug,
        service,
        encrypted,
        body.identity,
        body.metadata,
        body.expiresAt ? new Date(body.expiresAt) : undefined,
      )
      return c.json({ ok: true, vault: vaultSlug, service })
    },
  )

  app.delete(
    '/vaults/:slug/credentials/:service',
    requireToken,
    requireVaultAdmin('slug'),
    async c => {
      const db = c.get('db')
      const deleted = await deleteCredential(db, c.req.param('slug'), c.req.param('service'))
      if (!deleted) return c.json({ error: 'Credential not found' }, 404)
      return c.json({ ok: true })
    },
  )

  // ─── Service Catalog ──────────────────────────────────────────────────────

  app.get('/services', async c => {
    const token = extractBearerToken(c.req.header('Authorization'))
    if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

    const db = c.get('db')
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const allServices = await listServices(db)

    const mgmt = extractManagementRights(token, publicKeyHex)
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

  app.put('/services/:service', requireToken, requireRight('manage_services'), async c => {
    const service = c.req.param('service')
    if (RESERVED_PATHS.has(service)) {
      return c.json({ error: `'${service}' is a reserved name` }, 400)
    }

    const body = await c.req.json<{
      baseUrl: string
      authMethod?: string
      headerName?: string
      headerScheme?: string
      displayName?: string
      description?: string
      oauthClientId?: string
      oauthClientSecret?: string
      oauthAuthorizeUrl?: string
      oauthTokenUrl?: string
      oauthScopes?: string
      supportedAuthMethods?: string[]
      apiType?: string
      docsUrl?: string
      preview?: unknown
      authConfig?: Record<string, unknown>
    }>()

    if (!body.baseUrl) return c.json({ error: 'baseUrl is required' }, 400)

    const db = c.get('db')
    await upsertService(db, service, {
      baseUrl: body.baseUrl,
      authMethod: body.authMethod,
      headerName: body.headerName,
      headerScheme: body.headerScheme,
      displayName: body.displayName,
      description: body.description,
      oauthClientId: body.oauthClientId,
      oauthClientSecret: body.oauthClientSecret,
      oauthAuthorizeUrl: body.oauthAuthorizeUrl,
      oauthTokenUrl: body.oauthTokenUrl,
      oauthScopes: body.oauthScopes,
      supportedAuthMethods: body.supportedAuthMethods
        ? JSON.stringify(body.supportedAuthMethods)
        : undefined,
      apiType: body.apiType,
      docsUrl: body.docsUrl,
      preview: body.preview ? JSON.stringify(body.preview) : undefined,
      authConfig: body.authConfig ? JSON.stringify(body.authConfig) : undefined,
    })

    return c.json({ ok: true, service })
  })

  app.delete('/services/:service', requireToken, requireRight('manage_services'), async c => {
    const db = c.get('db')
    const deleted = await deleteService(db, c.req.param('service'))
    if (!deleted) return c.json({ error: 'Service not found' }, 404)
    return c.json({ ok: true })
  })

  // ─── Token Management ─────────────────────────────────────────────────────

  app.post('/tokens/mint', requireToken, async c => {
    const body = await c.req.json<{
      grants?: ProxyConstraint[]
      bindings?: Record<string, { vault: string }>
      rights?: string[]
      vaultAdmin?: string[]
    }>()

    const mgmt = c.get('managementRights')!

    // Mint management tokens
    if (body.rights || body.vaultAdmin) {
      if (!mgmt.rights.includes('manage_vaults') && !mgmt.vaultAdminSlugs.includes('*')) {
        return c.json({ error: 'Forbidden: requires "manage_vaults" right' }, 403)
      }
      try {
        const token = mintManagementToken(
          c.env.BISCUIT_PRIVATE_KEY,
          body.rights ?? [],
          body.vaultAdmin ?? [],
        )
        const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
        return c.json({ token, publicKey })
      } catch (e) /* v8 ignore start */ {
        return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
      } /* v8 ignore stop */
    }

    // Mint proxy tokens with bindings format
    if (body.bindings && Object.keys(body.bindings).length > 0) {
      for (const [, binding] of Object.entries(body.bindings)) {
        const allowed =
          mgmt.vaultAdminSlugs.includes('*') || mgmt.vaultAdminSlugs.includes(binding.vault)
        if (!allowed) {
          return c.json(
            { error: `Forbidden: no vault_admin for "${binding.vault}"` },
            403,
          )
        }
      }

      const grants: ProxyConstraint[] = Object.entries(body.bindings).map(
        ([service, binding]) => ({
          services: service,
          vault: binding.vault,
        }),
      )

      try {
        const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, grants)
        const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
        return c.json({ token, publicKey })
      } catch (e) /* v8 ignore start */ {
        return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
      } /* v8 ignore stop */
    }

    // Mint proxy tokens with grants format
    if (body.grants && body.grants.length > 0) {
      for (const grant of body.grants) {
        if (grant.vault) {
          const allowed =
            mgmt.vaultAdminSlugs.includes('*') || mgmt.vaultAdminSlugs.includes(grant.vault)
          if (!allowed) {
            return c.json(
              { error: `Forbidden: no vault_admin for "${grant.vault}"` },
              403,
            )
          }
        }
      }

      try {
        const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, body.grants)
        const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
        return c.json({ token, publicKey })
      } catch (e) /* v8 ignore start */ {
        return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
      } /* v8 ignore stop */
    }

    return c.json(
      { error: 'One of grants, bindings, rights, or vaultAdmin is required' },
      400,
    )
  })

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

  app.post('/tokens/revoke', requireToken, async c => {
    const body = await c.req.json<{ token: string; reason?: string }>()
    if (!body.token) return c.json({ error: 'token is required' }, 400)

    try {
      const db = c.get('db')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const revIds = getRevocationIds(body.token, publicKeyHex)
      for (const id of revIds) {
        await revokeToken(db, id, body.reason)
      }
      return c.json({ ok: true, revokedIds: revIds })
    } catch (e) {
      return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
    }
  })

  app.post('/keys/generate', requireToken, requireRight('manage_services'), async c => {
    return c.json(generateKeyPairHex())
  })

  // ─── Auth Flows ────────────────────────────────────────────────────────────

  app.route('/auth', oauthRoutes)
  app.route('/auth', apiKeyRoutes)

  app.get('/auth/status/:flowId', async c => {
    const db = c.get('db')
    const flow = await getAuthFlow(db, c.req.param('flowId'))

    if (!flow) return c.json({ error: 'Flow not found' }, 404)
    if (flow.expiresAt < new Date()) return c.json({ error: 'Flow expired' }, 404)

    if (flow.status === 'completed') {
      return c.json({ status: 'completed', token: flow.wardenToken, identity: flow.identity })
    }

    return c.json({ status: 'pending' }, 202)
  })

  // ─── Documentation (must be before proxy catch-all) ──────────────────────

  app.route('/', docRoutes())

  // ─── Discovery (content-negotiated) ────────────────────────────────────────

  app.get('/:service', async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()

    const db = c.get('db')
    const svc = await getService(db, serviceName)
    if (!svc) return c.json({ error: `Unknown service: ${serviceName}` }, 404)

    const token = extractBearerToken(c.req.header('Authorization'))
    const json = wantsJson(c.req.header('Accept'))

    if (!token) {
      if (json) {
        return c.json(buildUnauthDiscovery(svc, c.env.BASE_URL), 401, {
          'WWW-Authenticate': 'Bearer realm="warden"',
        })
      }
      return c.html(ServiceLandingPage({ service: svc }))
    }

    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const vaultSlug = extractVaultFromToken(token, publicKeyHex, serviceName) ?? 'personal'
    const cred = await getCredential(db, vaultSlug, serviceName)
    const identity = cred?.identity ?? 'default'

    if (json) {
      return c.json(buildAuthDiscovery(svc, identity, c.env.BASE_URL))
    }
    return c.html(ServiceLandingPage({ service: svc, identity }))
  })

  // ─── Legacy redirect ──────────────────────────────────────────────────────

  app.all('/proxy/:service/*', async c => {
    const service = c.req.param('service')
    const url = new URL(c.req.url)
    const rest = url.pathname.slice(`/proxy/${service}`.length)
    return c.redirect(`/${service}${rest}${url.search}`, 301)
  })

  // ─── Proxy ─────────────────────────────────────────────────────────────────

  app.all('/:service/*', async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()

    const url = new URL(c.req.url)
    const upstreamPath = url.pathname.slice(`/${serviceName}`.length) || '/'

    return handleProxy(c, serviceName, upstreamPath)
  })

  return app
}
