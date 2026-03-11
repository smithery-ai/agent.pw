import type { Context } from 'hono'
import type { CoreHonoEnv } from './core/types'
import {
  authorizeRequest,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import {
  getCredProfilesByHostWithPublicFallback,
  getCredProfilesBySlugWithPublicFallback,
  getCredential,
  getCredentialsByHostWithinRoot,
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
import {
  credentialName,
  joinCredentialPath,
  pathDepth,
  isAncestorOrEqual,
  validatePath,
} from './paths'
import { coveringRootsForPath, rootsForAction } from './rights'

function pickDeepestMatches<T extends { path: string }>(matches: T[]) {
  if (matches.length === 0) {
    return { selected: null, conflicts: [] as T[] }
  }

  const topDepth = pathDepth(matches[0].path)
  const conflicts = matches.filter(match => pathDepth(match.path) === topDepth)
  if (conflicts.length > 1) {
    return { selected: null, conflicts }
  }

  return { selected: matches[0], conflicts: [] as T[] }
}

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

export const PROXY_TOKEN_HEADER = 'Proxy-Authorization'
export const CREDENTIAL_SELECTOR_HEADER = 'agentpw-credential'
export const REQUESTED_ROOT_HEADER = 'agentpw-root'

function buildAgentPwChallenge(params: Record<string, string | undefined>) {
  const encoded = Object.entries(params)
    .filter(([, value]) => typeof value === 'string' && value.length > 0)
    .map(([key, value]) => `${key}="${String(value).replace(/"/g, '\\"')}"`)
    .join(', ')
  return `AgentPW ${encoded}`.trimEnd()
}

function buildAuthorizationUri(
  authBaseUrl: string | undefined,
  profileSlug: string | undefined,
  hostname: string,
) {
  if (!authBaseUrl) return undefined

  const returnTo = profileSlug
    ? `/auth/${encodeURIComponent(profileSlug)}`
    : `/auth/manual?target=${encodeURIComponent(hostname)}`

  return `${authBaseUrl.replace(/\/$/, '')}/auth/login?return_to=${encodeURIComponent(returnTo)}`
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null
  return header.startsWith('Bearer ') ? header.slice(7) : header
}

export function extractProxyToken(
  proxyAuthorizationHeader: string | undefined,
): string | null {
  return extractBearerToken(proxyAuthorizationHeader)
}

function shouldRefresh(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  const expiresMs = new Date(expiresAt).getTime()
  if (Number.isNaN(expiresMs)) return false
  return expiresMs - Date.now() <= 5 * 60 * 1000
}

async function refreshCredentialIfNeeded(
  c: Context<CoreHonoEnv>,
  cred: {
    host: string
    path: string
    auth: Record<string, unknown>
    secret: Buffer
  },
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
    host: cred.host,
    path: cred.path,
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
  const proxyHeader = PROXY_TOKEN_HEADER.toLowerCase()
  const requestedRootHeader = REQUESTED_ROOT_HEADER.toLowerCase()
  c.req.raw.headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (lower === 'host' || lower === 'act-as') return
    if (lower === requestedRootHeader) return
    if (lower === proxyHeader || lower === CREDENTIAL_SELECTOR_HEADER) return
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
  const token = extractProxyToken(c.req.header(PROXY_TOKEN_HEADER))
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

  const tokenFacts = extractTokenFacts(token, publicKeyHex)
  c.set('tokenFacts', tokenFacts)
  const useRoots = rootsForAction(tokenFacts.rights, 'credential.use')
  if (useRoots.length === 0) {
    return c.json({ error: 'Forbidden: requires "credential.use" right' }, 403)
  }

  const selector = c.req.header(CREDENTIAL_SELECTOR_HEADER)
  const requestedRootHeader = c.req.header(REQUESTED_ROOT_HEADER)
  let requestedRoot: string | null = null

  if (requestedRootHeader) {
    if (!validatePath(requestedRootHeader) || requestedRootHeader === '/') {
      if (requestedRootHeader !== '/') {
        return c.json({ error: `Invalid requested root '${requestedRootHeader}'` }, 400)
      }
    }
    if (!useRoots.includes(requestedRootHeader)) {
      return c.json({ error: `Forbidden: token cannot use requested root '${requestedRootHeader}'` }, 403)
    }
    requestedRoot = requestedRootHeader
  } else if (useRoots.length === 1) {
    requestedRoot = useRoots[0]
  } else if (selector?.startsWith('/')) {
    const roots = coveringRootsForPath(useRoots, selector)
    if (roots.length === 1) {
      requestedRoot = roots[0]
    } else if (roots.length === 0) {
      return c.json({ error: `Token cannot use credential '${selector}'` }, 403)
    } else if (roots.length > 1) {
      return c.json({
        error: 'Multiple roots match the requested credential path',
        roots,
        hint: `Send the ${REQUESTED_ROOT_HEADER} header to choose a root explicitly.`,
      }, 409)
    }
  }

  if (!requestedRoot) {
    return c.json({
      error: 'Multiple credential roots are available',
      roots: useRoots,
      hint: `Send the ${REQUESTED_ROOT_HEADER} header to choose a root explicitly.`,
    }, 409)
  }

  const resource = slug ?? hostname
  const result = authorizeRequest(token, publicKeyHex, resource, c.req.method, upstreamPath, {
    action: 'credential.use',
    host: hostname,
    requestedRoot,
  })
  if (!result.authorized) {
    return c.json({ error: 'Forbidden', details: result.error }, 403)
  }

  let profile: { path: string; host: string[] } | null = null
  if (slug) {
    const matches = await getCredProfilesBySlugWithPublicFallback(db, slug, requestedRoot)
    const { selected, conflicts } = pickDeepestMatches(matches)
    if (conflicts.length > 0) {
      return c.json({
        error: `Multiple profiles named '${slug}' match inside '${requestedRoot}'`,
        profilePaths: conflicts.map(candidate => candidate.path),
        hint: `Choose a different active root with ${REQUESTED_ROOT_HEADER} or make the profile path unique.`,
      }, 409)
    }
    profile = selected
  } else {
    const matches = await getCredProfilesByHostWithPublicFallback(db, hostname, requestedRoot)
    const { selected, conflicts } = pickDeepestMatches(matches)
    if (conflicts.length > 0) {
      return c.json({
        error: `Multiple profiles match host '${hostname}' inside '${requestedRoot}'`,
        profilePaths: conflicts.map(candidate => candidate.path),
        hint: `Send the ${REQUESTED_ROOT_HEADER} header to narrow the request or use an explicit profile slug.`,
      }, 409)
    }
    profile = selected
  }

  if (slug && !profile) {
    return c.json({ error: `Unknown credential profile: ${slug}` }, 404)
  }

  if (profile && !profile.host.includes(hostname)) {
    return c.json({ error: `Host '${hostname}' is not allowed for profile '${profile.path}'` }, 403)
  }

  let cred: Awaited<ReturnType<typeof getCredential>> | null = null
  if (selector) {
    const selectedPath = selector.startsWith('/') ? selector : joinCredentialPath(requestedRoot, selector)
    if (!validatePath(selectedPath) || selectedPath === '/') {
      return c.json({ error: `Invalid credential selector '${selector}'` }, 400)
    }
    const selected = await getCredential(db, hostname, selectedPath)
    if (!selected) {
      return c.json({ error: `Unknown credential: ${selector}` }, 404)
    }
    if (!isAncestorOrEqual(requestedRoot, selected.path)) {
      return c.json({ error: `Token cannot use credential '${selector}'` }, 403)
    }
    cred = selected
  } else {
    const matches = await getCredentialsByHostWithinRoot(db, hostname, requestedRoot)
    if (matches.length > 1) {
      const topDepth = pathDepth(matches[0].path)
      const sameDepth = matches.filter(m => pathDepth(m.path) === topDepth)
      if (sameDepth.length > 1) {
        return c.json({
          error: `Multiple credentials match host '${hostname}' inside '${requestedRoot}' at the same path depth`,
          credentialNames: sameDepth.map(match => credentialName(match.path)),
          hint: `Send the ${CREDENTIAL_SELECTOR_HEADER} header to choose a credential name explicitly.`,
        }, 409)
      }
    }
    cred = matches[0] ?? null
  }

  // Build upstream request — hostname comes from the URL, always HTTPS
  const url = new URL(c.req.url)
  const upstreamUrl = `https://${hostname}${upstreamPath}${url.search}`

  const headers = buildUpstreamHeaders(c)
  const body = await readRequestBody(c)
  const explicitAuthorization = headers.has('Authorization')

  const log = c.get('logger')
  log.info({
    slug: profile?.path ?? slug,
    hostname,
    method: c.req.method,
    requestedRoot,
    upstreamUrl,
    credential: cred ? credentialName(cred.path) : null,
  }, 'proxy request')

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
    responseHeaders.append('WWW-Authenticate', buildAgentPwChallenge({
      target_host: hostname,
      profile: profile?.path,
      authorization_uri: buildAuthorizationUri(c.env.CLI_AUTH_BASE_URL, profile?.path, hostname),
    }))

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    })
  }

  log.info({
    slug: profile?.path ?? slug,
    hostname,
    method: c.req.method,
    requestedRoot,
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
