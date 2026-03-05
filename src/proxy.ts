import type { Context } from 'hono'
import type { CoreHonoEnv } from './core/types'
import {
  authorizeRequest,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import { getCredential, getService, isRevoked, upsertCredential } from './db/queries'
import {
  decryptCredentials,
  encryptCredentials,
  buildCredentialHeaders,
  type StoredCredentials,
} from './lib/credentials-crypto'
import { refreshOAuthToken } from './lib/oauth-refresh'
import { isDnsError } from './lib/dns'

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null
  return header.startsWith('Bearer ') ? header.slice(7) : header
}

function shouldRefresh(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  const expiresMs = new Date(expiresAt).getTime()
  if (Number.isNaN(expiresMs)) return false
  return expiresMs - Date.now() <= 5 * 60 * 1000
}

async function refreshCredentialIfNeeded(
  c: Context<CoreHonoEnv>,
  service: Awaited<ReturnType<typeof getService>>,
  userId: string,
  cred: Awaited<ReturnType<typeof getCredential>>,
  stored: StoredCredentials,
): Promise<StoredCredentials> {
  if (!service || !cred || !stored.oauth?.refreshToken) {
    return stored
  }
  if (!shouldRefresh(stored.oauth.expiresAt)) {
    return stored
  }

  const authConfig: Record<string, string> = service.authConfig
    ? JSON.parse(service.authConfig)
    : {}

  const refreshed = await refreshOAuthToken({
    tokenUrl: stored.oauth.tokenUrl,
    refreshToken: stored.oauth.refreshToken,
    clientId: stored.oauth.clientId,
    clientSecret: stored.oauth.clientSecret,
    scopes: stored.oauth.scopes,
    authConfig,
  })

  const nextStored: StoredCredentials = {
    ...stored,
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, refreshed.accessToken),
    oauth: {
      ...stored.oauth,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      expiresAt: refreshed.expiresAt,
    },
  }

  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, nextStored)
  await upsertCredential(c.get('db'), userId, service.service, 'default', encrypted)

  return nextStored
}

export async function handleProxy(
  c: Context<CoreHonoEnv>,
  service: string,
  upstreamPath: string,
) {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const db = c.get('db')
  const svc = await getService(db, service)
  if (!svc) return c.json({ error: `Unknown service: ${service}` }, 404)

  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

  // Check revocation
  try {
    const revIds = getRevocationIds(token, publicKeyHex)
    for (const id of revIds) {
      if (await isRevoked(db, id)) {
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

  // Resolve userId: admin tokens can use ?user= to act as another user
  const facts = extractTokenFacts(token, publicKeyHex)
  const userParam = c.req.query('user')
  let userId: string | null
  if (facts.rights.includes('admin') && userParam) {
    userId = userParam
  } else {
    userId = facts.userId
  }
  if (!userId) {
    return c.json({ error: 'No identity in token' }, 403)
  }

  // Look up credential by (userId, service)
  const cred = await getCredential(db, userId, service)
  if (!cred) {
    return c.json({ error: `No credential found for ${service}` }, 404)
  }

  // Build upstream request — strip internal "user" param before forwarding
  const url = new URL(c.req.url)
  url.searchParams.delete('user')
  const upstreamSearch = url.searchParams.toString() ? `?${url.searchParams.toString()}` : ''
  const upstreamUrl = `${svc.baseUrl.replace(/\/$/, '')}${upstreamPath}${upstreamSearch}`

  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'authorization') return
    if (key.toLowerCase() === 'host') return
    headers.set(key, value)
  })

  const log = c.get('logger')
  log.info({ service, userId, method: c.req.method, upstreamUrl }, 'proxy request')

  // Inject credential headers (after logging to avoid leaking secrets)
  let stored = await decryptCredentials(c.env.ENCRYPTION_KEY, cred.encryptedCredentials)
  try {
    stored = await refreshCredentialIfNeeded(c, svc, userId, cred, stored)
  } catch (e) {
    return c.json({ error: `OAuth token refresh failed: ${errorMessage(e)}` }, 401)
  }
  for (const [name, value] of Object.entries(stored.headers)) {
    headers.set(name, value)
  }

  // Forward request
  let body: ArrayBuffer | undefined
  if (['GET', 'HEAD'].includes(c.req.method)) {
    body = undefined
  } else {
    body = await c.req.raw.arrayBuffer()
  }

  let upstream: Response
  try {
    upstream = await fetch(upstreamUrl, {
      method: c.req.method,
      headers,
      body,
    })
  } catch (error) {
    const hostname = new URL(upstreamUrl).hostname
    if (isDnsError(error)) {
      return c.json({
        error: `DNS resolution failed for ${hostname}`,
        hint: 'The hostname does not resolve. Verify the service URL is correct.',
      }, 502)
    }
    return c.json({
      error: `Failed to reach upstream: ${errorMessage(error)}`,
      hint: `Could not connect to ${hostname}. The service may be down or unreachable.`,
    }, 502)
  }

  log.info({
    service,
    userId,
    method: c.req.method,
    upstreamUrl,
    status: upstream.status,
    responseHeaders: Object.fromEntries(upstream.headers.entries()),
  }, 'proxy response')

  // Return response transparently
  const responseHeaders = new Headers(upstream.headers)
  responseHeaders.delete('transfer-encoding')

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  })
}
