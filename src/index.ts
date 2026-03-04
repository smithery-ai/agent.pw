import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { streamSSE } from 'hono/streaming'
import type { HonoEnv, ProxyConstraint } from './types'
import { createDb, type Database } from './db/index'
import { Redis } from '@upstash/redis'
import {
  mintToken,
  mintManagementToken,
  restrictToken,
  extractGrants,
  extractManagementRights,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
} from './biscuit'
import {
  getService,
  listServices,
  upsertService,
  deleteService,
  listCredentials,
  listCredentialsForService,
  upsertCredential,
  deleteCredential,
  revokeToken,
  listServicesWithCredentialCounts,
  countCredentialsForService,
  listDocPages,
  getDocPage,
} from './db/queries'
import { createAuthFlow, getAuthFlow } from './lib/auth-flow-store'
import { extractBearerToken, handleProxy } from './proxy'
import { requireToken, requireRight, requireVaultAdmin, optionalSession, requireBrowserSession } from './middleware'
import { buildUnauthDiscovery, buildAuthDiscovery, buildWardenGuide, buildWardenOnboarding, wantsJson } from './discovery'
import { oauthRoutes, encryptSecret } from './oauth'
import { apiKeyRoutes } from './api-key'
import { workosRoutes } from './workos'
import { probeOAuthWellKnown } from './discovery/probe'
import { getKnownOAuthProvider } from './oauth-providers'
import { AuthPage, ErrorPage, ServiceLandingPage, WardenLandingPage } from './ui'
import { docRoutes } from './discovery/serve'
import { triggerDiscoveryWorkflow, isDiscoveryStale } from './discovery/index'
import { encryptCredentials, buildCredentialHeaders } from './lib/credentials-crypto'
import { mergeServicePreviewWithInferredIcon } from './service-preview'
import { parseAuthSchemes, getOAuthScheme, getApiKeyScheme, DEFAULT_API_KEY_SCHEME, type AuthScheme } from './auth-schemes'
import { webhookRoutes } from './webhooks/index'

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function deriveDisplayName(hostname: string) {
  // api.linear.app → Linear, api.github.com → Github
  const parts = hostname.replace(/^(api|www)\./, '').split('.')
  const name = parts[0]
  return name.charAt(0).toUpperCase() + name.slice(1)
}

const RESERVED_PATHS = new Set(['auth', 'tokens', 'services', 'vaults', 'keys', 'proxy', 'hooks', '.well-known', 'favicon.ico'])

const FILE_EXTENSIONS = new Set([
  'json', 'html', 'htm', 'xml', 'php', 'asp', 'aspx', 'axd', 'jsp', 'cgi',
  'action', 'env', 'txt', 'yaml', 'yml', 'config', 'conf', 'log', 'bak',
  'sql', 'db', 'csv', 'js', 'css', 'map', 'ts', 'py', 'rb', 'pl',
  'png', 'jpg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot',
])

/** Filter out auto-registered junk (file paths, bare words) — only keep real hostnames. */
function looksLikeHostname(service: string) {
  if (!service.includes('.')) return false
  if (service.startsWith('.')) return false
  return !FILE_EXTENSIONS.has(service.split('.').pop()!.toLowerCase())
}

interface AppDeps {
  db?: Database
  redis?: Redis
  biscuitPrivateKey?: string
  baseUrl?: string
  encryptionKey?: string
  anthropicApiKey?: string
  anthropicBaseUrl?: string
  awsAccessKeyId?: string
  awsSecretAccessKey?: string
  awsRegion?: string
  workosClientId?: string
  workosApiKey?: string
  workosCookiePassword?: string
}

export function createApp(deps: AppDeps = {}) {
  const app = new Hono<HonoEnv>()

  app.onError((err, c) => {
    console.error(`[error] ${c.req.method} ${c.req.path}:`, err.message, err.stack)
    return c.json({ error: 'Internal Server Error' }, 500)
  })

  // ─── Global middleware ─────────────────────────────────────────────────────

  app.use('*', cors())

  // Redirect if user accidentally pasted a full URL as the path
  // e.g. /https://api.linear.app/graphql → /api.linear.app/graphql
  app.use('*', async (c, next) => {
    const url = new URL(c.req.url)
    const match = url.pathname.match(/^\/https?:\/\/?(.+)/)
    if (match) {
      return c.redirect(`/${match[1]}${url.search}`, 301)
    }
    return next()
  })

  app.use('*', async (c, next) => {
    if (!c.env) c.env = {} as HonoEnv['Bindings']
    if (deps.baseUrl) {
      c.env.BASE_URL = deps.baseUrl
    } else if (!c.env.BASE_URL) {
      const reqUrl = new URL(c.req.url)
      // Preserve existing test/Node behavior while using true origin in deployed workers.
      c.env.BASE_URL =
        reqUrl.hostname === 'localhost' && !reqUrl.port
          ? `${reqUrl.protocol}//${reqUrl.hostname}:3000`
          : reqUrl.origin
    }
    // Override env only when deps are provided (Node.js / tests)
    if (deps.biscuitPrivateKey) c.env.BISCUIT_PRIVATE_KEY = deps.biscuitPrivateKey
    if (deps.encryptionKey) c.env.ENCRYPTION_KEY = deps.encryptionKey
    if (deps.anthropicApiKey) c.env.ANTHROPIC_API_KEY = deps.anthropicApiKey
    if (deps.anthropicBaseUrl) c.env.ANTHROPIC_BASE_URL = deps.anthropicBaseUrl
    if (deps.awsAccessKeyId) c.env.AWS_ACCESS_KEY_ID = deps.awsAccessKeyId
    if (deps.awsSecretAccessKey) c.env.AWS_SECRET_ACCESS_KEY = deps.awsSecretAccessKey
    if (deps.awsRegion) c.env.AWS_REGION = deps.awsRegion
    if (deps.workosClientId) c.env.WORKOS_CLIENT_ID = deps.workosClientId
    if (deps.workosApiKey) c.env.WORKOS_API_KEY = deps.workosApiKey
    if (deps.workosCookiePassword) c.env.WORKOS_COOKIE_PASSWORD = deps.workosCookiePassword

    if (deps.db) {
      c.set('db', deps.db)
    } else if (c.env.HYPERDRIVE) {
      c.set('db', createDb(c.env.HYPERDRIVE.connectionString))
    }

    if (deps.redis) {
      c.set('redis', deps.redis)
    } else if (c.env.KV_REST_API_URL && c.env.KV_REST_API_TOKEN) {
      c.set('redis', new Redis({ url: c.env.KV_REST_API_URL, token: c.env.KV_REST_API_TOKEN }))
    }
    return next()
  })

  // ─── Health ────────────────────────────────────────────────────────────────

  app.get('/', async c => {
    const accept = c.req.header('Accept')
    if (wantsJson(accept)) {
      return c.json(buildWardenGuide(c.env.BASE_URL))
    }

    const db = c.get('db')
    const recentServices = await listServicesWithCredentialCounts(db)
    const filtered = recentServices.filter(s => looksLikeHostname(s.service))
    return c.html(WardenLandingPage({ services: filtered }))
  })

  // ─── Credential Management (org-scoped, vault_admin checks use org_id) ────

  app.get('/vaults/:slug/credentials', requireToken, requireVaultAdmin('slug'), async c => {
    const db = c.get('db')
    const orgId = c.req.param('slug')
    const creds = await listCredentials(db, orgId)
    return c.json(
      creds.map(cr => ({
        service: cr.service,
        slug: cr.slug,
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
      const orgId = c.req.param('slug')
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
    },
  )

  app.delete(
    '/vaults/:slug/credentials/:service',
    requireToken,
    requireVaultAdmin('slug'),
    async c => {
      const db = c.get('db')
      const orgId = c.req.param('slug')
      const credSlug = c.req.query('slug') ?? 'default'
      const deleted = await deleteCredential(db, orgId, c.req.param('service'), credSlug)
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
      authSchemes?: AuthScheme[]
      displayName?: string
      description?: string
      oauthClientId?: string
      oauthClientSecret?: string
      apiType?: string
      docsUrl?: string
      preview?: unknown
      authConfig?: Record<string, unknown>
      webhookConfig?: Record<string, unknown>
    }>()

    if (!body.baseUrl) return c.json({ error: 'baseUrl is required' }, 400)

    const db = c.get('db')
    const existing = await getService(db, service)
    const displayName = body.displayName ?? existing?.displayName ?? deriveDisplayName(service)
    const preview =
      body.preview !== undefined
        ? mergeServicePreviewWithInferredIcon(service, body.preview, displayName)
        : existing
          ? undefined
          : mergeServicePreviewWithInferredIcon(service, undefined, displayName)

    await upsertService(db, service, {
      baseUrl: body.baseUrl,
      authSchemes: body.authSchemes ? JSON.stringify(body.authSchemes) : undefined,
      displayName: body.displayName,
      description: body.description,
      oauthClientId: body.oauthClientId,
      encryptedOauthClientSecret: body.oauthClientSecret
        ? await encryptSecret(c.env.ENCRYPTION_KEY, body.oauthClientSecret)
        : undefined,
      apiType: body.apiType,
      docsUrl: body.docsUrl,
      preview: preview ? JSON.stringify(preview) : undefined,
      authConfig: body.authConfig ? JSON.stringify(body.authConfig) : undefined,
      webhookConfig: body.webhookConfig ? JSON.stringify(body.webhookConfig) : undefined,
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

  app.route('/auth', workosRoutes)

  // Tabbed auth page — requires browser session
  app.get('/auth/:service', requireBrowserSession, async c => {
    const serviceName = c.req.param('service')
    const db = c.get('db')
    const svc = await getService(db, serviceName)

    if (!svc) {
      return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)
    }

    const flowId = c.req.query('flow_id') ?? randomId()

    // Ensure a flow exists for polling
    const existingFlow = await getAuthFlow(c.get('redis'), flowId)
    if (!existingFlow) {
      await createAuthFlow(c.get('redis'), {
        id: flowId,
        service: serviceName,
        method: 'api_key',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      })
    }

    const callbackUrl = `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`
    return c.html(AuthPage({ service: svc, flowId, callbackUrl }))
  })

  app.route('/auth', oauthRoutes)
  app.route('/auth', apiKeyRoutes)

  app.get('/auth/status/:flowId', async c => {
    const redis = c.get('redis')
    const flowId = c.req.param('flowId')
    const accept = c.req.header('Accept')

    // SSE mode — hold connection until flow completes
    if (accept?.includes('text/event-stream')) {
      return streamSSE(c, async (stream) => {
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const flow = await getAuthFlow(redis, flowId)
          if (!flow) {
            await stream.writeSSE({ event: 'error', data: JSON.stringify({ error: 'Flow not found or expired' }) })
            return
          }
          if (flow.status === 'completed') {
            await stream.writeSSE({
              event: 'complete',
              data: JSON.stringify({ status: 'completed', token: flow.wardenToken, identity: flow.identity }),
            })
            return
          }
          await stream.writeSSE({ event: 'pending', data: JSON.stringify({ status: 'pending' }) })
          await new Promise(r => setTimeout(r, 2000))
        }
      })
    }

    // Fallback: JSON polling (backward compat)
    const flow = await getAuthFlow(redis, flowId)
    if (!flow) return c.json({ error: 'Flow not found' }, 404)

    if (flow.status === 'completed') {
      return c.json({ status: 'completed', token: flow.wardenToken, identity: flow.identity })
    }

    return c.json({ status: 'pending' }, 202)
  })

  // ─── Documentation (must be before proxy catch-all) ──────────────────────

  app.route('/', docRoutes())

  // ─── Webhooks (must be before proxy catch-all) ─────────────────────────────

  app.route('/', webhookRoutes())

  // ─── Discovery (content-negotiated) ────────────────────────────────────────

  app.get('/:service', optionalSession, async c => {
    const serviceName = c.req.param('service')
    if (RESERVED_PATHS.has(serviceName)) return c.notFound()
    if (!looksLikeHostname(serviceName)) return c.notFound()

    const db = c.get('db')
    let svc = await getService(db, serviceName)
    let isNew = false

    // Auto-register unknown services, attempting OAuth detection up front.
    if (!svc) {
      console.log(`[discovery] auto-registering new service: ${serviceName}`)
      const baseUrl = `https://${serviceName}`
      const displayName = deriveDisplayName(serviceName)
      const knownProvider = getKnownOAuthProvider(serviceName)

      let authSchemes: AuthScheme[]
      if (knownProvider) {
        authSchemes = knownProvider.authSchemes
      } else {
        const oauthWellKnown = await probeOAuthWellKnown(baseUrl)
        authSchemes = [DEFAULT_API_KEY_SCHEME]
        if (oauthWellKnown) {
          authSchemes.push({
            type: 'oauth2',
            authorizeUrl: oauthWellKnown.authorizeUrl,
            tokenUrl: oauthWellKnown.tokenUrl,
            scopes: oauthWellKnown.scopes,
          })
        }
      }

      await upsertService(db, serviceName, {
        baseUrl,
        displayName,
        authSchemes: JSON.stringify(authSchemes),
        authConfig: knownProvider ? JSON.stringify(knownProvider.authConfig) : undefined,
        webhookConfig: knownProvider?.webhookConfig ? JSON.stringify(knownProvider.webhookConfig) : undefined,
        preview: JSON.stringify(mergeServicePreviewWithInferredIcon(serviceName, undefined, displayName)),
      })
      svc = await getService(db, serviceName)
      if (!svc) return c.json({ error: `Failed to register service: ${serviceName}` }, 500)
      isNew = true
    } else {
      const knownProvider = getKnownOAuthProvider(serviceName)

      if (knownProvider) {
        // Known providers are the source of truth — sync auth schemes if mismatched
        // (fixes migration backfill from incorrect legacy auth_method values)
        const expectedSchemes = JSON.stringify(knownProvider.authSchemes)
        if (svc.authSchemes !== expectedSchemes) {
          console.log(`[discovery] syncing auth schemes for known provider: ${serviceName}`)
          await upsertService(db, serviceName, {
            baseUrl: svc.baseUrl,
            authSchemes: expectedSchemes,
            authConfig: JSON.stringify(knownProvider.authConfig),
          })
          svc = await getService(db, serviceName)
          if (!svc) return c.json({ error: `Failed to update service: ${serviceName}` }, 500)
        }
      } else if (!getOAuthScheme(parseAuthSchemes(svc.authSchemes))) {
        // Probe for OAuth on unknown services that lack an OAuth scheme
        const oauthWellKnown = await probeOAuthWellKnown(`https://${serviceName}`)
        if (oauthWellKnown) {
          console.log(`[discovery] backfilling OAuth for existing service: ${serviceName}`)
          const existingSchemes = parseAuthSchemes(svc.authSchemes)
          if (existingSchemes.length === 0) {
            existingSchemes.push(DEFAULT_API_KEY_SCHEME)
          }
          existingSchemes.push({
            type: 'oauth2',
            authorizeUrl: oauthWellKnown.authorizeUrl,
            tokenUrl: oauthWellKnown.tokenUrl,
            scopes: oauthWellKnown.scopes,
          })
          await upsertService(db, serviceName, {
            baseUrl: svc.baseUrl,
            authSchemes: JSON.stringify(existingSchemes),
            authConfig: svc.authConfig ?? undefined,
          })
          svc = await getService(db, serviceName)
          if (!svc) return c.json({ error: `Failed to update service: ${serviceName}` }, 500)
        }
      }
    }

    // Kick off discovery pipeline if stale or no docs exist
    const discoveryCtx = { db, hostname: serviceName, service: svc, anthropicApiKey: c.env.ANTHROPIC_API_KEY, anthropicBaseUrl: c.env.ANTHROPIC_BASE_URL, awsAccessKeyId: c.env.AWS_ACCESS_KEY_ID, awsSecretAccessKey: c.env.AWS_SECRET_ACCESS_KEY, awsRegion: c.env.AWS_REGION, baseUrl: c.env.BASE_URL, workflow: c.env.DISCOVERY_WORKFLOW }
    const stale = await isDiscoveryStale(discoveryCtx)
    if (stale) {
      console.log(`[discovery] triggering pipeline for ${serviceName} (${isNew ? 'new service' : 'stale'})`)
      // Non-blocking: workflow handles its own lifecycle
      triggerDiscoveryWorkflow(discoveryCtx).catch(err =>
        console.error(`[discovery] pipeline failed for ${serviceName}:`, err),
      )
    }

    // Build discovery status from doc metadata
    const docs = await listDocPages(db, serviceName)
    const meta = await getDocPage(db, serviceName, '_meta.json')
    const discoveryStatus = meta
      ? JSON.parse(meta.content!)
      : { pipeline_state: docs.length === 0 ? 'probing' : 'idle', total_pages: docs.length }

    // Check for saved credentials (if user is signed in)
    const session = c.get('session')
    let userCredentials: { slug: string; updatedAt: Date }[] | undefined
    if (session) {
      const creds = await listCredentialsForService(db, session.orgId, serviceName)
      if (creds.length > 0) {
        userCredentials = creds.map(cr => ({ slug: cr.slug, updatedAt: cr.updatedAt }))
      }
    }

    const token = extractBearerToken(c.req.header('Authorization'))
    const json = wantsJson(c.req.header('Accept'))

    const credentialCount = await countCredentialsForService(db, serviceName)

    if (!token) {
      if (json) {
        // Create an auth flow so the agent can poll/SSE for completion
        const flowId = randomId()
        await createAuthFlow(c.get('redis'), {
          id: flowId,
          service: serviceName,
          method: 'api_key',
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        })
        return c.json({ ...buildUnauthDiscovery(svc, c.env.BASE_URL, flowId), credential_count: credentialCount, discovery: discoveryStatus }, 401, {
          'WWW-Authenticate': 'Bearer realm="warden"',
        })
      }
      return c.html(ServiceLandingPage({ service: svc, discoveryStatus, userCredentials }))
    }

    if (json) {
      return c.json({ ...buildAuthDiscovery(svc, c.env.BASE_URL), credential_count: credentialCount, discovery: discoveryStatus })
    }
    return c.html(ServiceLandingPage({ service: svc, discoveryStatus, userCredentials }))
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
