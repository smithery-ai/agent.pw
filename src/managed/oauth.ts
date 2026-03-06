import { Hono } from 'hono'
import type { HonoEnv } from './types'
import { getService, upsertCredential, createAuthFlow, getAuthFlow, completeAuthFlow } from '../db/queries'
import { mintToken } from '../biscuit'
import { requireBrowserSession } from './middleware'
import { getSessionFromCookie } from './session'
import { SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders, importAesKey } from '../lib/credentials-crypto'
import { parseAuthSchemes, getOAuthScheme } from '../auth-schemes'
import { randomId, validateFlowId } from '../lib/utils'

export const oauthRoutes = new Hono<HonoEnv>()

type ServiceOAuthConfig = {
  authSchemes: string | null
  oauthClientId: string | null
  encryptedOauthClientSecret: Buffer | null
}

export type ResolvedOAuthConfig = {
  clientId: string
  clientSecret?: string
  authorizeUrl: string
  tokenUrl: string
  scopes?: string
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

export async function resolveOAuthConfig(
  encryptionKey: string,
  svc: ServiceOAuthConfig,
): Promise<ResolvedOAuthConfig | null> {
  const oauthScheme = getOAuthScheme(parseAuthSchemes(svc.authSchemes))
  if (!oauthScheme) return null

  if (svc.oauthClientId) {
    return {
      clientId: svc.oauthClientId,
      clientSecret: await decryptSecret(encryptionKey, svc.encryptedOauthClientSecret),
      authorizeUrl: oauthScheme.authorizeUrl,
      tokenUrl: oauthScheme.tokenUrl,
      scopes: oauthScheme.scopes,
    }
  }

  return null
}

// ─── Start OAuth ─────────────────────────────────────────────────────────────

oauthRoutes.get('/:slug/oauth', requireBrowserSession, async c => {
  const slug = c.req.param('slug')
  const db = c.get('db')
  const svc = await getService(db, slug)

  if (!svc) {
    return c.json({ error: `Unknown service: ${slug}` }, 404)
  }

  const session = c.get('session')
  const orgId = session?.orgId ?? 'local'

  const oauth = await resolveOAuthConfig(c.env.ENCRYPTION_KEY, svc)

  if (!oauth) {
    return c.json({ error: `OAuth not configured for ${slug}` }, 400)
  }

  const flowId = validateFlowId(c.req.query('flow_id')) ?? randomId()
  const codeVerifier = randomId() + randomId() // 96 chars
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  await createAuthFlow(c.get('db'), {
    id: flowId,
    slug,
    method: 'oauth',
    codeVerifier,
    orgId,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  })

  const params = new URLSearchParams({
    client_id: oauth.clientId,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${slug}/oauth/callback`,
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

oauthRoutes.get('/:slug/oauth/callback', async c => {
  const slug = c.req.param('slug')
  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')

  if (error) {
    return c.html(ErrorPage({ message: `OAuth error: ${error}` }), 400)
  }
  if (!code || !state) {
    return c.html(ErrorPage({ message: 'Missing code or state parameter' }), 400)
  }

  const db = c.get('db')
  const flow = await getAuthFlow(db, state)

  if (!flow) {
    return c.html(ErrorPage({ message: 'Unknown or expired auth flow' }), 400)
  }
  if (flow.slug !== slug) {
    return c.html(ErrorPage({ message: 'Auth flow service mismatch' }), 400)
  }
  if (flow.status === 'completed') {
    return c.html(ErrorPage({ message: 'Auth flow already completed' }), 400)
  }

  const svc = await getService(db, slug)
  if (!svc) {
    return c.html(ErrorPage({ message: `Unknown service: ${slug}` }), 500)
  }

  // Resolve orgId from session (survives redirect via SameSite=Lax) or flow
  const session = await getSessionFromCookie(c.req.header('Cookie'), c.env.WORKOS_COOKIE_PASSWORD as string)
  const orgId = session?.orgId ?? flow.orgId
  if (!orgId) {
    return c.html(ErrorPage({ message: 'Session expired. Please try again.' }), 400)
  }

  const oauth = await resolveOAuthConfig(c.env.ENCRYPTION_KEY, svc)

  if (!oauth) {
    return c.html(ErrorPage({ message: `OAuth not configured for ${slug}` }), 500)
  }

  if (!flow.codeVerifier) {
    return c.html(ErrorPage({ message: 'Missing OAuth PKCE verifier on auth flow' }), 500)
  }

  const authConfig: Record<string, string> = svc.authConfig ? JSON.parse(svc.authConfig) : {}

  const tokenBody: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${slug}/oauth/callback`,
    code_verifier: flow.codeVerifier,
  }

  const tokenHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  if (authConfig.token_auth === 'basic' && oauth.clientSecret) {
    tokenHeaders.Authorization = `Basic ${btoa(`${oauth.clientId}:${oauth.clientSecret}`)}`
  } else {
    tokenBody.client_id = oauth.clientId
    if (oauth.clientSecret) {
      tokenBody.client_secret = oauth.clientSecret
    }
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
  await upsertCredential(db, orgId, slug, 'default', encrypted)

  // Mint token with user identity
  const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, orgId)

  // Complete the flow in DB
  await completeAuthFlow(db, state, { token, identity, orgId })

  return c.html(SuccessPage({ token, service: svc }))
})
