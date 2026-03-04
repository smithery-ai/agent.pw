import { Hono, type Context } from 'hono'
import type { HonoEnv } from './types'
import type { Database } from './db/index'
import { getService, upsertCredential, getOAuthApp, upsertOAuthApp } from './db/queries'
import { createAuthFlow, getAuthFlow, completeAuthFlow } from './lib/auth-flow-store'
import { mintToken } from './biscuit'
import { requireBrowserSession } from './middleware'
import { getSessionFromCookie } from './lib/session'
import { SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders, importAesKey } from './lib/credentials-crypto'
import { parseAuthSchemes, getOAuthScheme } from './auth-schemes'

export const oauthRoutes = new Hono<HonoEnv>()

type OAuthSource = 'managed' | 'byo'

type ServiceOAuthConfig = {
  authSchemes: string | null
  oauthClientId: string | null
  encryptedOauthClientSecret: Buffer | null
}

export type ResolvedOAuthConfig = {
  source: OAuthSource
  clientId: string
  clientSecret?: string
  authorizeUrl: string
  tokenUrl: string
  scopes?: string
}

function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

export async function encryptSecret(encryptionKey: string, secret: string): Promise<Buffer> {
  const key = await importAesKey(encryptionKey)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(secret)
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  const result = Buffer.alloc(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

async function decryptSecret(
  encryptionKey: string,
  encryptedSecret?: Buffer | null,
): Promise<string | undefined> {
  if (!encryptedSecret) return undefined
  if (encryptedSecret.length < 12 + 16) throw new Error('Invalid encrypted client secret')

  const key = await importAesKey(encryptionKey)
  const iv = encryptedSecret.subarray(0, 12)
  const ciphertext = encryptedSecret.subarray(12)
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  return new TextDecoder().decode(plaintext)
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

async function generateCodeChallenge(verifier: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function parseTokenPayload(tokenRes: Response): Promise<Record<string, unknown>> {
  const text = await tokenRes.text()
  const contentType = tokenRes.headers.get('content-type') ?? ''

  if (contentType.includes('application/json') || text.trim().startsWith('{')) {
    return JSON.parse(text) as Record<string, unknown>
  }

  const params = new URLSearchParams(text)
  const payload: Record<string, unknown> = {}
  for (const [key, value] of params.entries()) {
    payload[key] = value
  }
  return payload
}

function resolveExpiresAt(tokenData: Record<string, unknown>): string | undefined {
  const expiresAtRaw = tokenData.expires_at
  if (typeof expiresAtRaw === 'string') {
    const parsed = new Date(expiresAtRaw)
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString()
  }

  const expiresInRaw = tokenData.expires_in
  if (typeof expiresInRaw === 'number' && Number.isFinite(expiresInRaw)) {
    return new Date(Date.now() + expiresInRaw * 1000).toISOString()
  }
  if (typeof expiresInRaw === 'string') {
    const n = Number.parseInt(expiresInRaw, 10)
    if (!Number.isNaN(n)) {
      return new Date(Date.now() + n * 1000).toISOString()
    }
  }

  return undefined
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}

function parseOAuthSource(raw: string | undefined): OAuthSource | undefined {
  if (raw === 'managed' || raw === 'byo') return raw
  return undefined
}

export async function resolveOAuthConfig(
  db: Database,
  encryptionKey: string,
  service: string,
  orgId: string,
  svc: ServiceOAuthConfig,
  preferredSource?: OAuthSource,
): Promise<ResolvedOAuthConfig | null> {
  const oauthScheme = getOAuthScheme(parseAuthSchemes(svc.authSchemes))
  if (!oauthScheme) return null

  if (preferredSource !== 'managed') {
    const app = await getOAuthApp(db, orgId, service)
    if (app) {
      return {
        source: 'byo',
        clientId: app.clientId,
        clientSecret: await decryptSecret(encryptionKey, app.encryptedClientSecret),
        authorizeUrl: oauthScheme.authorizeUrl,
        tokenUrl: oauthScheme.tokenUrl,
        scopes: app.scopes ?? oauthScheme.scopes,
      }
    }
  }

  if (preferredSource === 'byo') {
    return null
  }

  if (svc.oauthClientId) {
    return {
      source: 'managed',
      clientId: svc.oauthClientId,
      clientSecret: await decryptSecret(encryptionKey, svc.encryptedOauthClientSecret),
      authorizeUrl: oauthScheme.authorizeUrl,
      tokenUrl: oauthScheme.tokenUrl,
      scopes: oauthScheme.scopes,
    }
  }

  return null
}

export async function refreshOAuthToken(params: {
  tokenUrl: string
  refreshToken: string
  clientId: string
  clientSecret?: string
  scopes?: string
  authConfig?: Record<string, string>
}) {
  const tokenBody: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: params.refreshToken,
    client_id: params.clientId,
  }

  if (params.clientSecret) {
    tokenBody.client_secret = params.clientSecret
  }
  if (params.scopes) {
    tokenBody.scope = params.scopes
  }

  const tokenHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  if (params.authConfig?.token_accept) {
    tokenHeaders.Accept = params.authConfig.token_accept
  }

  const tokenRes = await fetch(params.tokenUrl, {
    method: 'POST',
    headers: tokenHeaders,
    body: new URLSearchParams(tokenBody).toString(),
  })

  if (!tokenRes.ok) {
    const text = await tokenRes.text()
    throw new Error(`Token refresh failed: ${text}`)
  }

  const tokenData = await parseTokenPayload(tokenRes)
  const accessToken =
    (params.authConfig?.token_path
      ? getNestedValue(tokenData, params.authConfig.token_path)
      : tokenData.access_token) as string

  if (!accessToken) {
    throw new Error('No access token in refresh response')
  }

  const refreshToken =
    (params.authConfig?.refresh_token_path
      ? getNestedValue(tokenData, params.authConfig.refresh_token_path)
      : tokenData.refresh_token) as string | undefined

  return {
    accessToken,
    refreshToken: asString(refreshToken) ?? params.refreshToken,
    expiresAt: resolveExpiresAt(tokenData),
  }
}

// ─── Start OAuth ─────────────────────────────────────────────────────────────

oauthRoutes.get('/:service/oauth', requireBrowserSession, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) {
    return c.json({ error: `Unknown service: ${serviceName}` }, 404)
  }

  const session = c.get('session')!
  const orgId = session.orgId
  const source = parseOAuthSource(c.req.query('source'))

  const oauth = await resolveOAuthConfig(
    db,
    c.env.ENCRYPTION_KEY,
    serviceName,
    orgId,
    svc,
    source,
  )

  if (!oauth) {
    return c.json({ error: `OAuth not configured for ${serviceName}` }, 400)
  }

  const flowId = randomId()
  const codeVerifier = randomId() + randomId() // 96 chars
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  await createAuthFlow(c.get('redis'), {
    id: flowId,
    service: serviceName,
    method: 'oauth',
    codeVerifier,
    orgId,
    oauthSource: oauth.source,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  })

  const params = new URLSearchParams({
    client_id: oauth.clientId,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`,
    state: flowId,
    response_type: 'code',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  if (oauth.scopes) {
    params.set('scope', oauth.scopes)
  }

  return c.redirect(`${oauth.authorizeUrl}?${params.toString()}`)
})

// ─── Store BYO OAuth App + Start OAuth ──────────────────────────────────────

oauthRoutes.post('/:service/oauth/byo', requireBrowserSession, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) {
    return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)
  }

  const oauthScheme = getOAuthScheme(parseAuthSchemes(svc.authSchemes))
  if (!oauthScheme) {
    return c.html(
      ErrorPage({ message: `OAuth endpoints are not known for ${serviceName} yet` }),
      400,
    )
  }

  const session = c.get('session')!
  const orgId = session.orgId

  const contentType = c.req.header('Content-Type') ?? ''
  let clientId = ''
  let clientSecret = ''
  let scopes = ''

  if (contentType.includes('application/json')) {
    const body = await c.req.json<{
      client_id?: string
      client_secret?: string
      scopes?: string
    }>()
    clientId = body.client_id?.trim() ?? ''
    clientSecret = body.client_secret?.trim() ?? ''
    scopes = body.scopes?.trim() ?? ''
  } else {
    const formData = await c.req.parseBody()
    clientId = ((formData.client_id as string) ?? '').trim()
    clientSecret = ((formData.client_secret as string) ?? '').trim()
    scopes = ((formData.scopes as string) ?? '').trim()
  }

  if (!clientId) {
    return c.html(ErrorPage({ message: 'client_id is required' }), 400)
  }

  await upsertOAuthApp(db, orgId, serviceName, {
    clientId,
    encryptedClientSecret: clientSecret
      ? await encryptSecret(c.env.ENCRYPTION_KEY, clientSecret)
      : null,
    scopes: scopes || undefined,
  })

  // Now initiate the OAuth flow with the BYO app
  const oauth = await resolveOAuthConfig(db, c.env.ENCRYPTION_KEY, serviceName, orgId, svc, 'byo')
  if (!oauth) {
    return c.html(ErrorPage({ message: 'Failed to resolve BYO OAuth config' }), 500)
  }

  const flowId = randomId()
  const codeVerifier = randomId() + randomId()
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  await createAuthFlow(c.get('redis'), {
    id: flowId,
    service: serviceName,
    method: 'oauth',
    codeVerifier,
    orgId,
    oauthSource: 'byo',
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  })

  const params = new URLSearchParams({
    client_id: oauth.clientId,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`,
    state: flowId,
    response_type: 'code',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  if (oauth.scopes) {
    params.set('scope', oauth.scopes)
  }

  return c.redirect(`${oauth.authorizeUrl}?${params.toString()}`)
})

// ─── OAuth Callback ──────────────────────────────────────────────────────────

oauthRoutes.get('/:service/oauth/callback', async c => {
  const serviceName = c.req.param('service')
  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')

  if (error) {
    return c.html(ErrorPage({ message: `OAuth error: ${error}` }), 400)
  }
  if (!code || !state) {
    return c.html(ErrorPage({ message: 'Missing code or state parameter' }), 400)
  }

  const redis = c.get('redis')
  const db = c.get('db')
  const flow = await getAuthFlow(redis, state)

  if (!flow) {
    return c.html(ErrorPage({ message: 'Unknown or expired auth flow' }), 400)
  }
  if (flow.service !== serviceName) {
    return c.html(ErrorPage({ message: 'Auth flow service mismatch' }), 400)
  }
  if (flow.status === 'completed') {
    return c.html(ErrorPage({ message: 'Auth flow already completed' }), 400)
  }

  const svc = await getService(db, serviceName)
  if (!svc) {
    return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 500)
  }

  // Resolve orgId from session (survives redirect via SameSite=Lax) or flow
  const session = await getSessionFromCookie(c.req.header('Cookie'), c.env.WORKOS_COOKIE_PASSWORD)
  const orgId = session?.orgId ?? flow.orgId
  if (!orgId) {
    return c.html(ErrorPage({ message: 'Session expired. Please try again.' }), 400)
  }

  const sourceHint = parseOAuthSource(flow.oauthSource)
  const oauth = await resolveOAuthConfig(
    db,
    c.env.ENCRYPTION_KEY,
    serviceName,
    orgId,
    svc,
    sourceHint,
  )

  if (!oauth) {
    return c.html(ErrorPage({ message: `OAuth not configured for ${serviceName}` }), 500)
  }

  if (!flow.codeVerifier) {
    return c.html(ErrorPage({ message: 'Missing OAuth PKCE verifier on auth flow' }), 500)
  }

  const authConfig: Record<string, string> = svc.authConfig ? JSON.parse(svc.authConfig) : {}

  const tokenBody: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`,
    client_id: oauth.clientId,
    code_verifier: flow.codeVerifier,
  }

  if (oauth.clientSecret) {
    tokenBody.client_secret = oauth.clientSecret
  }

  const tokenHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  if (authConfig.token_accept) {
    tokenHeaders.Accept = authConfig.token_accept
  }

  const tokenRes = await fetch(oauth.tokenUrl, {
    method: 'POST',
    headers: tokenHeaders,
    body: new URLSearchParams(tokenBody).toString(),
  })

  if (!tokenRes.ok) {
    const text = await tokenRes.text()
    return c.html(ErrorPage({ message: `Token exchange failed: ${text}` }), 500)
  }

  const tokenData = await parseTokenPayload(tokenRes)
  const accessToken =
    (authConfig.token_path
      ? getNestedValue(tokenData, authConfig.token_path)
      : tokenData.access_token) as string

  if (!accessToken) {
    return c.html(ErrorPage({ message: 'No access token in response' }), 500)
  }

  const refreshToken =
    (authConfig.refresh_token_path
      ? getNestedValue(tokenData, authConfig.refresh_token_path)
      : tokenData.refresh_token) as string | undefined

  const tokenScopes = asString(tokenData.scope) ?? oauth.scopes
  const expiresAtIso = resolveExpiresAt(tokenData)

  // Determine identity via "whoami" call
  let identity = 'default'

  if (authConfig.identity_url) {
    try {
      const identityHeaders: Record<string, string> = {
        Authorization: `Bearer ${accessToken}`,
      }

      let identityRes: Response

      if (authConfig.identity_method === 'POST') {
        identityHeaders['Content-Type'] = 'application/json'
        identityRes = await fetch(authConfig.identity_url, {
          method: 'POST',
          headers: identityHeaders,
          body: authConfig.identity_body || undefined,
        })
      } else {
        identityRes = await fetch(authConfig.identity_url, { headers: identityHeaders })
      }

      if (identityRes.ok) {
        const identityData = (await identityRes.json()) as Record<string, unknown>
        const resolved = authConfig.identity_path
          ? getNestedValue(identityData, authConfig.identity_path)
          : undefined
        if (typeof resolved === 'string') {
          identity = resolved
        }
      }
    } catch {
      // Fall back to default identity.
    }
  }

  // Store credential with refresh token data
  const credHeaders = buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, accessToken)
  const storedCredentials: Parameters<typeof encryptCredentials>[1] = {
    headers: credHeaders,
  }

  if (typeof refreshToken === 'string') {
    storedCredentials.oauth = {
      refreshToken,
      accessToken,
      expiresAt: expiresAtIso,
      tokenUrl: oauth.tokenUrl,
      clientId: oauth.clientId,
      clientSecret: oauth.clientSecret,
      scopes: tokenScopes,
    }
  }

  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, storedCredentials)
  await upsertCredential(db, orgId, serviceName, 'default', encrypted)

  // Mint master biscuit — covers all services in user's org
  const workosUserId = session?.workosUserId ?? identity
  const wardenToken = mintToken(c.env.BISCUIT_PRIVATE_KEY, [
    { vault: orgId, metadata: { userId: workosUserId } },
  ])

  // Complete the flow in Redis
  await completeAuthFlow(redis, state, { wardenToken, identity, orgId })

  return c.html(SuccessPage({ token: wardenToken, service: svc }))
})
