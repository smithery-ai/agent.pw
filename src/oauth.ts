import { Hono } from 'hono'
import type { HonoEnv } from './types'
import { getService, createAuthFlow, getAuthFlow, completeAuthFlow, upsertCredential } from './db/queries'
import { mintToken } from './biscuit'
import { SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders } from './lib/credentials-crypto'

export const oauthRoutes = new Hono<HonoEnv>()

function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

async function generateCodeChallenge(verifier: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  // Base64url encode
  const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ─── Start OAuth ─────────────────────────────────────────────────────────────

oauthRoutes.get('/:service/oauth', async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) return c.json({ error: `Unknown service: ${serviceName}` }, 404)
  if (!svc.oauthAuthorizeUrl || !svc.oauthClientId) {
    return c.json({ error: `OAuth not configured for ${serviceName}` }, 400)
  }

  const flowId = randomId()
  const vaultSlug = c.req.query('vault') ?? 'personal'
  const codeVerifier = randomId() + randomId() // 96 chars
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  // Store flow
  await createAuthFlow(db, {
    id: flowId,
    service: serviceName,
    method: 'oauth',
    codeVerifier,
    vaultSlug,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
  })

  // Build authorize URL
  const params = new URLSearchParams({
    client_id: svc.oauthClientId,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`,
    state: flowId,
    response_type: 'code',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  if (svc.oauthScopes) {
    params.set('scope', svc.oauthScopes)
  }

  return c.redirect(`${svc.oauthAuthorizeUrl}?${params.toString()}`)
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

  const db = c.get('db')
  const flow = await getAuthFlow(db, state)

  if (!flow) {
    return c.html(ErrorPage({ message: 'Unknown or expired auth flow' }), 400)
  }
  if (flow.expiresAt < new Date()) {
    return c.html(ErrorPage({ message: 'Auth flow expired' }), 400)
  }
  if (flow.status === 'completed') {
    return c.html(ErrorPage({ message: 'Auth flow already completed' }), 400)
  }

  const svc = await getService(db, serviceName)
  if (!svc || !svc.oauthTokenUrl || !svc.oauthClientId) {
    return c.html(ErrorPage({ message: `OAuth not configured for ${serviceName}` }), 500)
  }

  // Exchange code for token
  const authConfig: Record<string, string> = svc.authConfig ? JSON.parse(svc.authConfig) : {}

  const tokenBody: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`,
    client_id: svc.oauthClientId,
    code_verifier: flow.codeVerifier!,
  }

  if (svc.oauthClientSecret) {
    tokenBody.client_secret = svc.oauthClientSecret
  }

  const tokenHeaders: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }

  // Some providers (GitHub) need Accept: application/json
  if (authConfig.token_accept) {
    tokenHeaders.Accept = authConfig.token_accept
  }

  const tokenRes = await fetch(svc.oauthTokenUrl, {
    method: 'POST',
    headers: tokenHeaders,
    body: new URLSearchParams(tokenBody).toString(),
  })

  if (!tokenRes.ok) {
    const text = await tokenRes.text()
    return c.html(ErrorPage({ message: `Token exchange failed: ${text}` }), 500)
  }

  const tokenData = await tokenRes.json() as Record<string, unknown>
  const accessToken =
    (authConfig.token_path
      ? getNestedValue(tokenData, authConfig.token_path)
      : tokenData.access_token) as string

  if (!accessToken) {
    return c.html(ErrorPage({ message: 'No access token in response' }), 500)
  }

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
      // Fall back to 'default' identity
    }
  }

  // Store credential in vault
  const vaultSlug = flow.vaultSlug ?? 'personal'
  const credHeaders = buildCredentialHeaders(svc, accessToken)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })
  await upsertCredential(db, vaultSlug, serviceName, encrypted, identity)

  // Mint Warden token with vault binding
  const wardenToken = mintToken(c.env.BISCUIT_PRIVATE_KEY, [
    { services: serviceName, vault: vaultSlug, metadata: { userId: identity } },
  ])

  // Complete the flow
  await completeAuthFlow(db, state, { wardenToken, identity })

  return c.html(SuccessPage({ token: wardenToken, service: svc }))
})

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}
