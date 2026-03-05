import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { CoreHonoEnv } from './types'
import type { Database } from '../db/index'
import { listServicesWithCredentialCounts } from '../db/queries'
import { createLogger } from '../lib/logger'
import { looksLikeHostname } from '../lib/utils'
import { deriveEncryptionKey } from '../lib/credentials-crypto'
import { credentialRoutes } from '../routes/credentials'
import { serviceRoutes } from '../routes/services'
import { tokenRoutes } from '../routes/tokens'
import { proxyRoutes } from '../routes/proxy'
import { buildJwks } from '../webhooks/envelope'
import { getPublicKeyHex } from '../biscuit'

export interface CoreAppDeps {
  db?: Database
  biscuitPrivateKey?: string
  baseUrl?: string
}

/**
 * Mounts the core route modules (vault, services, tokens, webhooks, proxy)
 * onto any Hono app. Used by both core and managed entry points.
 */
export function mountCoreRoutes(app: Hono<any>) {
  app.route('/credentials', credentialRoutes)
  app.route('/services', serviceRoutes)
  app.route('/tokens', tokenRoutes)

  // JWKS endpoint
  app.get('/.well-known/jwks.json', c => {
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    return c.json(buildJwks(publicKeyHex))
  })

  // Proxy catch-all (must be last)
  app.route('/', proxyRoutes)
}

/** Redirect /https://... → /proxy/... */
export function urlRedirectMiddleware(c: any, next: any) {
  const url = new URL(c.req.url)
  const match = url.pathname.match(/^\/https?:\/\/?(.+)/)
  if (match) {
    return c.redirect(`/proxy/${match[1]}${url.search}`, 301)
  }
  return next()
}

/** Log non-trivial requests with timing. */
export function requestLoggingMiddleware(c: any, next: any) {
  const start = performance.now()
  return next().then(() => {
    const duration = Math.round(performance.now() - start)
    const path = new URL(c.req.url).pathname
    if (path !== '/' && !path.startsWith('/favicon')) {
      c.get('logger').info({ method: c.req.method, path, status: c.res.status, duration_ms: duration }, 'request')
    }
    try { c.executionCtx?.waitUntil?.(c.get('flushLogger')()) } catch { /* no ExecutionContext in tests */ }
  })
}

/**
 * Creates the core Warden app — credential vault, proxy, tokens, webhooks.
 * No WorkOS, no browser sessions. Runs locally or embedded.
 */
export function createCoreApp(deps: CoreAppDeps = {}) {
  const app = new Hono<CoreHonoEnv>()

  app.onError((err, c) => {
    c.get('logger')?.error({ method: c.req.method, path: c.req.path, error: err.message, stack: err.stack }, 'unhandled error')
    return c.json({ error: 'Internal Server Error' }, 500)
  })

  app.use('*', cors())
  app.use('*', urlRedirectMiddleware)

  app.use('*', async (c, next) => {
    if (!c.env) c.env = {} as CoreHonoEnv['Bindings']
    if (deps.baseUrl) {
      c.env.BASE_URL = deps.baseUrl
    } else if (!c.env.BASE_URL) {
      const reqUrl = new URL(c.req.url)
      c.env.BASE_URL =
        reqUrl.hostname === 'localhost' && !reqUrl.port
          ? `${reqUrl.protocol}//${reqUrl.hostname}:3000`
          : reqUrl.origin
    }
    if (deps.biscuitPrivateKey) c.env.BISCUIT_PRIVATE_KEY = deps.biscuitPrivateKey
    c.env.ENCRYPTION_KEY = await deriveEncryptionKey(c.env.BISCUIT_PRIVATE_KEY)

    if (deps.db) {
      c.set('db', deps.db)
    }

    const { logger, flush } = createLogger('warden')
    c.set('logger', logger)
    c.set('flushLogger', flush)
    return next()
  })

  app.use('*', requestLoggingMiddleware)

  // ─── Health ────────────────────────────────────────────────────────────────

  app.get('/', async c => {
    const db = c.get('db')
    const recentServices = await listServicesWithCredentialCounts(db)
    const filtered = recentServices.filter(s => looksLikeHostname(s.service))
    return c.json({ services: filtered.map(s => ({ service: s.service, credentialCount: s.credentialCount })) })
  })

  mountCoreRoutes(app)

  return app
}
