import type { Context } from 'hono'
import type { CoreHonoEnv } from './core/types'
import {
  authorizeRequest,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import { getCredProfile, getCredentialsByHost, isRevoked, upsertCredential } from './db/queries'
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
  cred: { id: string; host: string; slug: string; auth: string; secret: Buffer },
  stored: StoredCredentials,
): Promise<StoredCredentials> {
  if (!stored.oauth?.refreshToken) {
    return stored
  }
  if (!shouldRefresh(stored.oauth.expiresAt)) {
    return stored
  }

  const refreshed = await refreshOAuthToken({
    tokenUrl: stored.oauth.tokenUrl,
    refreshToken: stored.oauth.refreshToken,
    clientId: stored.oauth.clientId,
    clientSecret: stored.oauth.clientSecret,
    scopes: stored.oauth.scopes,
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
  await upsertCredential(c.get('db'), {
    id: cred.id,
    host: cred.host,
    slug: cred.slug,
    auth: cred.auth,
    secret: encrypted,
  })

  return nextStored
}

export async function handleProxy(
  c: Context<CoreHonoEnv>,
  slug: string,
  hostname: string,
  upstreamPath: string,
) {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const db = c.get('db')
  const profile = await getCredProfile(db, slug)
  if (!profile) return c.json({ error: `Unknown service: ${slug}` }, 404)

  // Validate hostname against cred_profile hosts (SSRF prevention)
  const allowedHosts: string[] = JSON.parse(profile.host)
  if (!allowedHosts.includes(hostname)) {
    return c.json({ error: `Host '${hostname}' is not allowed for service '${slug}'` }, 403)
  }

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

  // Authorize (Biscuit resource is the slug)
  const result = authorizeRequest(token, publicKeyHex, slug, c.req.method, upstreamPath)
  if (!result.authorized) {
    return c.json({ error: 'Forbidden', details: result.error }, 403)
  }

  // Look up credential by hostname
  const creds = await getCredentialsByHost(db, hostname)
  const cred = creds[0]
  if (!cred) {
    return c.json({ error: `No credential found for ${hostname}` }, 404)
  }

  // Build upstream request — hostname comes from the URL, always HTTPS
  const url = new URL(c.req.url)
  const upstreamUrl = `https://${hostname}${upstreamPath}${url.search}`

  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'authorization') return
    if (key.toLowerCase() === 'host') return
    if (key.toLowerCase() === 'act-as') return
    headers.set(key, value)
  })

  const log = c.get('logger')
  log.info({ slug, hostname, method: c.req.method, upstreamUrl }, 'proxy request')

  // Inject credential headers (after logging to avoid leaking secrets)
  let stored = await decryptCredentials(c.env.ENCRYPTION_KEY, cred.secret)
  try {
    stored = await refreshCredentialIfNeeded(c, cred, stored)
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
    slug,
    hostname,
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
