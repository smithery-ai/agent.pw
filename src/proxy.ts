import type { Context } from 'hono'
import type { HonoEnv } from './types'
import {
  authorizeRequest,
  extractVaultFromToken,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import { getCredential, getService, isRevoked } from './db/queries'

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

export async function handleProxy(
  c: Context<HonoEnv>,
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

  // Extract vault from token (falls back to "personal")
  const vaultSlug = extractVaultFromToken(token, publicKeyHex, service) ?? 'personal'

  // Look up credential by (vault, service)
  const cred = await getCredential(db, vaultSlug, service)
  if (!cred) {
    return c.json({ error: `No credential found for ${service} in vault "${vaultSlug}"` }, 404)
  }

  // Build upstream request
  const url = new URL(c.req.url)
  const upstreamUrl = `${svc.baseUrl.replace(/\/$/, '')}${upstreamPath}${url.search}`

  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'authorization') return
    if (key.toLowerCase() === 'host') return
    headers.set(key, value)
  })

  // Inject credential
  if (svc.authMethod === 'bearer' || svc.authMethod === 'oauth2') {
    headers.set(svc.headerName, `${svc.headerScheme} ${cred.token}`)
  } else if (svc.authMethod === 'api_key') {
    headers.set(svc.headerName, cred.token)
  } else if (svc.authMethod === 'basic') {
    headers.set(svc.headerName, `Basic ${btoa(cred.token)}`)
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
}
