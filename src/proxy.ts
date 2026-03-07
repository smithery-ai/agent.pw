import type { Context } from 'hono'
import type { CoreHonoEnv } from './core/types'
import {
  AuthorizerBuilder,
  Biscuit,
  PublicKey,
  SignatureAlgorithm,
} from '@smithery/biscuit'
import {
  authorizeRequest,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import {
  getCredProfile,
  getCredProfileByHost,
  getCredentialBySlug,
  getCredentialsByHost,
  isRevoked,
  upsertCredential,
} from './db/queries'
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

export const PROXY_TOKEN_HEADER = 'agentpw-token'
export const CREDENTIAL_SELECTOR_HEADER = 'agentpw-credential'
const MAX_POLICY_AUTHORIZE_RETRIES = 2

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null
  return header.startsWith('Bearer ') ? header.slice(7) : header
}

export function extractProxyToken(
  agentPwTokenHeader: string | undefined,
  authorizationHeader?: string | undefined,
): string | null {
  return extractBearerToken(agentPwTokenHeader) ?? extractBearerToken(authorizationHeader)
}

function stripKeyPrefix(key: string) {
  return key.replace(/^ed25519\//, '')
}

function parsePublicKey(publicKeyHex: string) {
  return PublicKey.fromString(stripKeyPrefix(publicKeyHex), SignatureAlgorithm.Ed25519)
}

function escapeDatalog(s: string) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function normalizePolicy(policy: string) {
  const trimmed = policy.trim().replace(/;$/, '')
  if (!trimmed) return ''
  if (trimmed.includes('check if') || trimmed.includes('allow if') || trimmed.includes('deny if')) {
    return trimmed.endsWith(';') ? trimmed : `${trimmed};`
  }
  if (trimmed.includes('(') || trimmed.includes('$') || trimmed.includes(' and ') || trimmed.includes(' or ')) {
    return `check if ${trimmed};`
  }
  const escaped = escapeDatalog(trimmed)
  return `check if user("${escaped}") or user_id("${escaped}") or org_id("${escaped}") or apw_user_id("${escaped}") or apw_org_id("${escaped}");`
}

function tokenSatisfiesPolicy(
  tokenBase64: string,
  publicKeyHex: string,
  policy: string | null | undefined,
): boolean {
  if (!policy) return true

  try {
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(tokenBase64.replace(/^apw_/, ''), publicKey)
    const code = [
      `time(${new Date().toISOString()});`,
      normalizePolicy(policy),
      'allow if true;',
    ].join('\n')

    // Mirror authorizeRequest(): the first WASM authorizer call on a cold runner
    // can time out, which makes policy-gated credentials look unavailable.
    for (let attempt = 0; attempt < MAX_POLICY_AUTHORIZE_RETRIES; attempt++) {
      try {
        const ab = new AuthorizerBuilder()
        ab.addCode(code)
        const auth = ab.buildAuthenticated(token)
        auth.authorize()
        return true
      } catch {
        if (attempt === MAX_POLICY_AUTHORIZE_RETRIES - 1) return false
      }
    }
  } catch {
    return false
  }

  return false
}

function shouldRefresh(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  const expiresMs = new Date(expiresAt).getTime()
  if (Number.isNaN(expiresMs)) return false
  return expiresMs - Date.now() <= 5 * 60 * 1000
}

async function refreshCredentialIfNeeded(
  c: Context<CoreHonoEnv>,
  cred: { id: string; host: string; slug: string; auth: Record<string, unknown>; secret: Buffer },
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

function isIpLiteral(hostname: string) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/
  const v6 = /^\[?[0-9a-f:]+\]?$/i
  return v4.test(hostname) || v6.test(hostname)
}

function isPrivateOrLocalAddress(hostname: string) {
  const normalized = hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1')
  if (normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1') {
    return true
  }
  if (!isIpLiteral(normalized)) {
    return false
  }

  const parts = normalized.split('.').map(part => Number.parseInt(part, 10))
  if (parts.length === 4 && parts.every(Number.isFinite)) {
    const [a, b] = parts
    if (a === 10 || a === 127 || a === 0) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
  }

  return normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd')
}

function buildUpstreamHeaders(c: Context<CoreHonoEnv>) {
  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (lower === 'host' || lower === 'act-as') return
    if (lower === PROXY_TOKEN_HEADER || lower === CREDENTIAL_SELECTOR_HEADER) return
    headers.set(key, value)
  })
  return headers
}

async function readRequestBody(c: Context<CoreHonoEnv>) {
  if (['GET', 'HEAD'].includes(c.req.method)) {
    return undefined
  }
  return c.req.raw.arrayBuffer()
}

async function forwardUpstream(
  upstreamUrl: string,
  method: string,
  headers: Headers,
  body: ArrayBuffer | undefined,
) {
  return fetch(upstreamUrl, {
    method,
    headers,
    body,
    redirect: 'manual',
  })
}

export async function handleProxy(
  c: Context<CoreHonoEnv>,
  slug: string | undefined,
  hostname: string,
  upstreamPath: string,
) {
  const token = extractProxyToken(
    c.req.header(PROXY_TOKEN_HEADER),
    c.req.header('Authorization'),
  )
  if (!token) {
    return c.json({
      error: `Missing ${PROXY_TOKEN_HEADER} header`,
      hint: `Send your Biscuit token in the ${PROXY_TOKEN_HEADER} header.`,
    }, 401)
  }

  if (isPrivateOrLocalAddress(hostname)) {
    return c.json({ error: `Refusing to proxy local or private target '${hostname}'` }, 403)
  }

  const db = c.get('db')
  const profile = slug ? await getCredProfile(db, slug) : await getCredProfileByHost(db, hostname)
  if (slug && !profile) {
    return c.json({ error: `Unknown credential profile: ${slug}` }, 404)
  }

  if (profile && !profile.host.includes(hostname)) {
    return c.json({ error: `Host '${hostname}' is not allowed for profile '${profile.slug}'` }, 403)
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

  const resource = slug ?? hostname
  const result = authorizeRequest(token, publicKeyHex, resource, c.req.method, upstreamPath)
  if (!result.authorized) {
    return c.json({ error: 'Forbidden', details: result.error }, 403)
  }

  const selector = c.req.header(CREDENTIAL_SELECTOR_HEADER)

  let cred = null as Awaited<ReturnType<typeof getCredentialBySlug>> | Awaited<ReturnType<typeof getCredentialsByHost>>[number] | null
  if (selector) {
    const selected = await getCredentialBySlug(db, selector)
    if (!selected) {
      return c.json({ error: `Unknown credential: ${selector}` }, 404)
    }
    if (selected.host !== hostname) {
      return c.json({ error: `Credential '${selector}' does not match host '${hostname}'` }, 403)
    }
    if (!tokenSatisfiesPolicy(token, publicKeyHex, selected.execPolicy)) {
      return c.json({ error: `Token cannot use credential '${selector}'` }, 403)
    }
    cred = selected
  } else {
    const creds = await getCredentialsByHost(db, hostname)
    cred = creds.find(candidate => tokenSatisfiesPolicy(token, publicKeyHex, candidate.execPolicy)) ?? null
  }

  // Build upstream request — hostname comes from the URL, always HTTPS
  const url = new URL(c.req.url)
  const upstreamUrl = `https://${hostname}${upstreamPath}${url.search}`

  const headers = buildUpstreamHeaders(c)
  const body = await readRequestBody(c)
  const explicitAuthorization = headers.has('Authorization')

  const log = c.get('logger')
  log.info({ slug: profile?.slug ?? slug, hostname, method: c.req.method, upstreamUrl, credential: cred?.slug ?? null }, 'proxy request')

  if (cred) {
    let stored = await decryptCredentials(c.env.ENCRYPTION_KEY, cred.secret)
    try {
      stored = await refreshCredentialIfNeeded(c, cred, stored)
    } catch (e) {
      return c.json({ error: `OAuth token refresh failed: ${errorMessage(e)}` }, 401)
    }
    for (const [name, value] of Object.entries(stored.headers)) {
      if (!headers.has(name)) {
        headers.set(name, value)
      }
    }
  }

  let upstream: Response
  try {
    upstream = await forwardUpstream(upstreamUrl, c.req.method, headers, body)
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

  if (upstream.status === 401 && !cred && !explicitAuthorization) {
    const responseHeaders = new Headers(upstream.headers)
    if (profile) {
      responseHeaders.set('agentpw-profile', profile.slug)
      responseHeaders.set('agentpw-auth-url', `${c.env.BASE_URL}/auth/${profile.slug}`)
    } else {
      responseHeaders.set('agentpw-manual', `agent.pw cred add ${hostname} --auth headers -H "Authorization: Bearer {token:Access token}"`)
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    })
  }

  log.info({
    slug: profile?.slug ?? slug,
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
