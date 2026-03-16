import { Hono } from 'hono'
import type { Context, Next } from 'hono'
import { cors } from 'hono/cors'
import { describeRoute, resolver } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from './types'
import type { Database } from '../db/index'
import { listCredProfilesWithCredentialCounts } from '../db/queries'
import { createLogger } from '../lib/logger'
import { deriveEncryptionKey } from '../lib/credentials-crypto'
import { credentialRoutes } from '../routes/credentials'
import { credProfileRoutes } from '../routes/cred-profiles'
import { tokenRoutes } from '../routes/tokens'
import { proxyRoutes } from '../routes/proxy'
import { buildJwks } from '../webhooks/envelope'
import { getPublicKeyHex } from '../biscuit'

export interface CoreAppDeps {
  db?: Database
  biscuitPrivateKey?: string
  baseUrl?: string
  cliAuthBaseUrl?: string
}

/**
 * Mounts the core route modules (credentials, cred_profiles, tokens, proxy)
 * onto any Hono app. Used by both core and managed entry points.
 */
export function mountCoreRoutes(app: Hono<CoreHonoEnv>) {
  app.route('/credentials', credentialRoutes)
  app.route('/cred_profiles', credProfileRoutes)
  app.route('/tokens', tokenRoutes)

  // JWKS endpoint
  app.get('/.well-known/jwks.json',
    describeRoute({
      tags: ['auth'],
      summary: 'JWKS',
      description: 'Returns the JSON Web Key Set for Biscuit token verification.',
      responses: {
        200: { description: 'JWKS document' },
      },
    }),
    c => {
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      return c.json(buildJwks(publicKeyHex))
    },
  )

  // Proxy catch-all (must be last)
  app.route('/', proxyRoutes)
}

/** No-op middleware — URL prefix redirects removed (slug-based routing). */
export async function urlRedirectMiddleware(_c: Context<CoreHonoEnv>, next: Next) {
  return next()
}

/** Log non-trivial requests with timing. */
export function requestLoggingMiddleware(c: Context<CoreHonoEnv>, next: Next) {
  const start = performance.now()
  return next().then(() => {
    const duration = Math.round(performance.now() - start)
    const path = new URL(c.req.url).pathname
    if (path !== '/' && !path.startsWith('/favicon')) {
      c.get('logger').info({ method: c.req.method, path, status: c.res.status, duration_ms: duration }, 'request')
    }
    // Log flushing (if any) is handled by the deployment layer
  })
}

/**
 * Creates the core app — credential vault, proxy, tokens.
 * No WorkOS, no browser sessions. Runs locally or embedded.
 */
export function createCoreApp(deps: CoreAppDeps = {}) {
  const app = new Hono<CoreHonoEnv>()

  app.onError((err, c) => {
    c.get('logger')?.error({ method: c.req.method, path: c.req.path, error: err.message, stack: err.stack }, 'unhandled error')
    return c.json({ error: 'Internal Server Error' }, 500)
  })

  app.use('*', async (c, next) => {
    await next()

    if (c.req.header('Origin')) {
      c.res.headers.append('Vary', 'Origin')
    }

    if (
      c.req.method === 'OPTIONS'
      && c.req.header('Access-Control-Request-Private-Network') === 'true'
    ) {
      c.res.headers.set('Access-Control-Allow-Private-Network', 'true')
      c.res.headers.append('Vary', 'Access-Control-Request-Private-Network')
    }
  })
  app.use('*', cors({
    origin: origin => origin || '*',
    allowHeaders: [
      'Authorization',
      'Proxy-Authorization',
      'Content-Type',
      'agentpw-credential',
      'agentpw-path',
    ],
  }))
  app.use('*', urlRedirectMiddleware)

  app.use('*', async (c, next) => {
    // biome-ignore lint/plugin/no-type-assertion: Hono initializes env lazily, so we seed the mutable bindings object here.
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
    if (deps.cliAuthBaseUrl) c.env.CLI_AUTH_BASE_URL = deps.cliAuthBaseUrl
    c.env.ENCRYPTION_KEY = await deriveEncryptionKey(c.env.BISCUIT_PRIVATE_KEY)

    if (deps.db) {
      c.set('db', deps.db)
    }

    const { logger } = createLogger('agentpw')
    c.set('logger', logger)
    return next()
  })

  app.use('*', requestLoggingMiddleware)

  // ─── Health ────────────────────────────────────────────────────────────────

  const HealthProfileSchema = z.object({
    slug: z.string(),
    credentialCount: z.number(),
  })
  const HealthResponseSchema = z.object({
    profiles: z.array(HealthProfileSchema),
  }).meta({ id: 'HealthResponse' })

  app.get('/',
    describeRoute({
      tags: ['health'],
      summary: 'Health check',
      description: 'Returns a list of configured credential profiles with credential counts.',
      responses: {
        200: { description: 'Health status', content: { 'application/json': { schema: resolver(HealthResponseSchema) } } },
      },
    }),
    async c => {
      const db = c.get('db')
      const profiles = await listCredProfilesWithCredentialCounts(db)
      return c.json({ profiles: profiles.map(p => ({ slug: p.path, credentialCount: p.credentialCount })) })
    },
  )

  mountCoreRoutes(app)

  return app
}
