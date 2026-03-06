import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { HonoEnv } from './types'
import { createDb, type Database } from '../db/index'
import { listServicesWithCredentialCounts, getService } from '../db/queries'
import { createLogger } from '../lib/logger'
import { deriveEncryptionKey } from '../lib/credentials-crypto'
import { mountCoreRoutes, urlRedirectMiddleware, requestLoggingMiddleware } from '../core/app'
import { authRoutes } from './routes/auth'

interface AppDeps {
  db?: Database
  biscuitPrivateKey?: string
  baseUrl?: string
  workosClientId?: string
  workosApiKey?: string
  workosCookiePassword?: string
}

export function createApp(deps: AppDeps = {}) {
  const app = new Hono<HonoEnv>()

  app.onError((err, c) => {
    c.get('logger')?.error({ method: c.req.method, path: c.req.path, error: err.message, stack: err.stack }, 'unhandled error')
    return c.json({ error: 'Internal Server Error' }, 500)
  })

  // ─── Global middleware ─────────────────────────────────────────────────────

  app.use('*', cors())
  app.use('*', urlRedirectMiddleware)

  app.use('*', async (c, next) => {
    if (!c.env) c.env = {} as HonoEnv['Bindings']
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
    if (deps.workosClientId) c.env.WORKOS_CLIENT_ID = deps.workosClientId
    if (deps.workosApiKey) c.env.WORKOS_API_KEY = deps.workosApiKey
    if (deps.workosCookiePassword) c.env.WORKOS_COOKIE_PASSWORD = deps.workosCookiePassword

    if (deps.db) {
      c.set('db', deps.db)
    } else if (c.env.HYPERDRIVE) {
      c.set('db', createDb(c.env.HYPERDRIVE.connectionString))
    }

    const { logger, flush } = createLogger('warden', c.env.BETTERSTACK_ERRORS_DSN)
    c.set('logger', logger)
    c.set('flushLogger', flush)
    return next()
  })

  app.use('*', requestLoggingMiddleware)

  // ─── Public catalog API (no auth required) ──────────────────────────────────

  app.get('/api/catalog', async c => {
    const db = c.get('db')
    const allServices = await listServicesWithCredentialCounts(db)
    return c.json({ services: allServices })
  })

  app.get('/api/catalog/:slug', async c => {
    const db = c.get('db')
    const svc = await getService(db, c.req.param('slug'))
    if (!svc) return c.json({ error: 'Service not found' }, 404)
    return c.json({
      slug: svc.slug,
      displayName: svc.displayName,
      description: svc.description,
      allowedHosts: svc.allowedHosts,
      docsUrl: svc.docsUrl,
      authSchemes: svc.authSchemes,
      hasOAuth: !!svc.oauthClientId,
    })
  })

  // ─── Managed root (redirect to frontend) ──────────────────────────────────

  app.get('/', c => {
    const frontendUrl = c.env.FRONTEND_URL
    if (frontendUrl) return c.redirect(frontendUrl)
    // Fallback: return catalog JSON
    return c.redirect('/api/catalog')
  })

  // ─── Auth routes ────────────────────────────────────────────────────────────

  app.route('/auth', authRoutes)

  // ─── Core routes (vault, services, tokens, webhooks, proxy) ─────────────

  mountCoreRoutes(app)

  return app
}
