// Webhook tests are disabled for v1. Re-enable for v2.
/* eslint-disable */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createApp } from '../src/managed/app'
import {
  createTestDb,
  BISCUIT_PRIVATE_KEY,
  TEST_SESSION_SECRET,
  TEST_ORG_ID,
  mintRootToken,
  mintProxyToken,
  type TestDb,
} from './setup'
import { getPublicKeyHex } from '../src/biscuit'
import { encryptCredentials, deriveEncryptionKey } from '../src/lib/credentials-crypto'
import { upsertService, upsertWebhookRegistration, getWebhookRegistration } from '../src/db/queries'
import { signEnvelope, buildJwks, extractRelevantHeaders, tryParseJson, randomId } from '../src/webhooks/envelope'
import { verifyWebhookSignature, verifySlackSignature, handleSlackChallenge } from '../src/webhooks/verify'

const TEST_ENCRYPTION_KEY = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)

let db: TestDb
let app: ReturnType<typeof createApp>

beforeEach(async () => {
  db = await createTestDb()
  app = createApp({ db, biscuitPrivateKey: BISCUIT_PRIVATE_KEY, workosCookiePassword: TEST_SESSION_SECRET })
})

function req(path: string, init?: RequestInit) {
  return app.request(path, init)
}

function mgmtReq(path: string, init: RequestInit = {}) {
  const token = mintRootToken()
  return req(path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...init.headers },
  })
}

async function seedServiceWithWebhookConfig(service = 'api.github.com', webhookConfig?: object) {
  await mgmtReq(`/services/${service}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseUrl: `https://${service}`,
      displayName: 'GitHub',
      authSchemes: [{ type: 'http', scheme: 'bearer' }],
      webhookConfig: webhookConfig ?? {
        signatureHeader: 'X-Hub-Signature-256',
        signaturePrefix: 'sha256=',
        algorithm: 'hmac-sha256',
        secretSource: 'client',
      },
    }),
  })
}

async function seedServiceWithCred(orgId = TEST_ORG_ID) {
  await seedServiceWithWebhookConfig()
  await mgmtReq(`/credentials/api.github.com?org=${orgId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'ghp_test123' }),
  })
}

// ─── JWKS Endpoint ────────────────────────────────────────────────────────────

describe.skip('JWKS Endpoint', () => {
  it('returns valid JWK with Ed25519 key', async () => {
    const res = await req('/.well-known/jwks.json')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.keys).toHaveLength(1)
    expect(body.keys[0].kty).toBe('OKP')
    expect(body.keys[0].crv).toBe('Ed25519')
    expect(body.keys[0].use).toBe('sig')
    expect(body.keys[0].kid).toBe('warden-ed25519-1')
    expect(body.keys[0].x).toBeDefined()
  })
})

// ─── Envelope & Signing ──────────────────────────────────────────────────────

describe.skip('Envelope', () => {
  it('signs and verifies envelope with Ed25519', async () => {
    const envelope = JSON.stringify({ test: 'data' })
    const signature = await signEnvelope(envelope, BISCUIT_PRIVATE_KEY)
    expect(signature).toMatch(/^[0-9a-f]+$/)
    expect(signature.length).toBe(128) // 64 bytes = 128 hex chars

    // Verify signature using public key
    const publicKeyHex = getPublicKeyHex(BISCUIT_PRIVATE_KEY).replace(/^ed25519\//, '')
    const publicKeyBytes = new Uint8Array(publicKeyHex.length / 2)
    for (let i = 0; i < publicKeyHex.length; i += 2) {
      publicKeyBytes[i / 2] = parseInt(publicKeyHex.substring(i, i + 2), 16)
    }

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )

    const sigBytes = new Uint8Array(signature.length / 2)
    for (let i = 0; i < signature.length; i += 2) {
      sigBytes[i / 2] = parseInt(signature.substring(i, i + 2), 16)
    }

    const valid = await crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      sigBytes,
      new TextEncoder().encode(envelope),
    )
    expect(valid).toBe(true)
  })

  it('buildJwks returns correct structure', () => {
    const publicKeyHex = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const jwks = buildJwks(publicKeyHex)
    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0].kty).toBe('OKP')
    expect(jwks.keys[0].crv).toBe('Ed25519')
    expect(jwks.keys[0].x).toBeTruthy()
  })

  it('extractRelevantHeaders picks service-specific headers', () => {
    const headers = new Headers({
      'Content-Type': 'application/json',
      'X-GitHub-Event': 'push',
      'X-Hub-Signature-256': 'sha256=abc',
      'Host': 'example.com',
      'Connection': 'keep-alive',
    })
    const result = extractRelevantHeaders(headers)
    expect(result['content-type']).toBe('application/json')
    expect(result['x-github-event']).toBe('push')
    expect(result['x-hub-signature-256']).toBe('sha256=abc')
    expect(result['host']).toBeUndefined()
    expect(result['connection']).toBeUndefined()
  })

  it('tryParseJson parses JSON body', () => {
    const body = new TextEncoder().encode('{"key":"value"}').buffer as ArrayBuffer
    expect(tryParseJson(body)).toEqual({ key: 'value' })
  })

  it('tryParseJson returns raw string for non-JSON', () => {
    const body = new TextEncoder().encode('not json').buffer as ArrayBuffer
    expect(tryParseJson(body)).toBe('not json')
  })
})

// ─── Webhook Verification ────────────────────────────────────────────────────

describe.skip('Webhook Verification', () => {
  it('verifies GitHub-style HMAC-SHA256 signature', async () => {
    const secret = 'test-secret'
    const body = new TextEncoder().encode('{"action":"push"}')

    // Compute valid HMAC
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, body)
    const sigHex = Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('')

    const headers = new Headers({
      'X-Hub-Signature-256': `sha256=${sigHex}`,
    })

    const valid = await verifyWebhookSignature(body.buffer as ArrayBuffer, headers, secret, {
      signatureHeader: 'X-Hub-Signature-256',
      signaturePrefix: 'sha256=',
      algorithm: 'hmac-sha256',
    })
    expect(valid).toBe(true)
  })

  it('rejects invalid HMAC signature', async () => {
    const body = new TextEncoder().encode('{"action":"push"}')
    const headers = new Headers({
      'X-Hub-Signature-256': 'sha256=0000000000000000000000000000000000000000000000000000000000000000',
    })

    const valid = await verifyWebhookSignature(body.buffer as ArrayBuffer, headers, 'test-secret', {
      signatureHeader: 'X-Hub-Signature-256',
      signaturePrefix: 'sha256=',
      algorithm: 'hmac-sha256',
    })
    expect(valid).toBe(false)
  })

  it('returns false when signature header is missing', async () => {
    const body = new TextEncoder().encode('test')
    const headers = new Headers()

    const valid = await verifyWebhookSignature(body.buffer as ArrayBuffer, headers, 'secret', {
      signatureHeader: 'X-Hub-Signature-256',
      algorithm: 'hmac-sha256',
    })
    expect(valid).toBe(false)
  })

  it('returns false for unknown algorithm', async () => {
    const body = new TextEncoder().encode('test')
    const headers = new Headers({ 'X-Sig': 'abc' })

    const valid = await verifyWebhookSignature(body.buffer as ArrayBuffer, headers, 'secret', {
      signatureHeader: 'X-Sig',
      algorithm: 'unknown-algo',
    })
    expect(valid).toBe(false)
  })

  it('handles Slack URL verification challenge', () => {
    const body = new TextEncoder().encode(JSON.stringify({
      type: 'url_verification',
      challenge: 'test-challenge-value',
    }))

    const response = handleSlackChallenge(body.buffer as ArrayBuffer)
    expect(response).not.toBeNull()
    // Read response body
    return response!.json().then((json: any) => {
      expect(json.challenge).toBe('test-challenge-value')
    })
  })

  it('returns null for non-challenge Slack events', () => {
    const body = new TextEncoder().encode(JSON.stringify({
      type: 'event_callback',
      event: { type: 'message' },
    }))

    const response = handleSlackChallenge(body.buffer as ArrayBuffer)
    expect(response).toBeNull()
  })

  it('verifies Slack signature format', async () => {
    const secret = 'slack-signing-secret'
    const timestamp = String(Math.floor(Date.now() / 1000))
    const bodyText = '{"type":"event_callback"}'
    const body = new TextEncoder().encode(bodyText)

    // Compute valid Slack signature: v0=HMAC-SHA256(secret, "v0:{timestamp}:{body}")
    const baseString = `v0:${timestamp}:${bodyText}`
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(baseString))
    const sigHex = Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('')

    const headers = new Headers({
      'X-Slack-Signature': `v0=${sigHex}`,
      'X-Slack-Request-Timestamp': timestamp,
    })

    const valid = await verifySlackSignature(body.buffer as ArrayBuffer, headers, secret)
    expect(valid).toBe(true)
  })

  it('rejects Slack signature with stale timestamp', async () => {
    const secret = 'slack-signing-secret'
    const timestamp = String(Math.floor(Date.now() / 1000) - 600) // 10 minutes ago
    const body = new TextEncoder().encode('{}')

    const headers = new Headers({
      'X-Slack-Signature': 'v0=abc',
      'X-Slack-Request-Timestamp': timestamp,
    })

    const valid = await verifySlackSignature(body.buffer as ArrayBuffer, headers, secret)
    expect(valid).toBe(false)
  })
})

// ─── Webhook Ingestion ───────────────────────────────────────────────────────

describe.skip('Webhook Ingestion', () => {
  it('returns 404 for unknown hook path', async () => {
    const res = await req('/hooks/api.github.com/nonexistent', { method: 'POST' })
    expect(res.status).toBe(404)
    const body = (await res.json()) as any
    expect(body.error).toContain('Unknown webhook endpoint')
  })

  it('forwards verified webhook to callback', async () => {
    await seedServiceWithWebhookConfig()

    const webhookSecret = 'wh-secret-123'
    const registrationId = randomId()

    const encryptedSecret = await encryptCredentials(TEST_ENCRYPTION_KEY, {
      headers: { secret: webhookSecret },
    })

    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/on-push',
      encryptedWebhookSecret: encryptedSecret,
    })

    // Compute valid HMAC signature for the payload
    const payload = JSON.stringify({ action: 'push', ref: 'refs/heads/main' })
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(webhookSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))
    const sigHex = Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('')

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))

    try {
      const res = await req(`/hooks/api.github.com/${registrationId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Hub-Signature-256': `sha256=${sigHex}`,
          'X-GitHub-Event': 'push',
        },
        body: payload,
      })

      expect(res.status).toBe(200)
      const body = (await res.json()) as any
      expect(body.ok).toBe(true)

      // Verify the callback was called with envelope
      const calls = (globalThis.fetch as any).mock.calls
      const callbackCall = calls.find((c: any) => c[0] === 'https://my-agent.run/on-push')
      expect(callbackCall).toBeTruthy()

      const callbackHeaders = callbackCall[1].headers as Record<string, string>
      expect(callbackHeaders['Warden-Signature']).toBeTruthy()
      expect(callbackHeaders['Warden-Event-Id']).toBeTruthy()
      expect(callbackHeaders['Content-Type']).toBe('application/json')

      // Verify envelope structure
      const envelope = JSON.parse(callbackCall[1].body)
      expect(envelope.warden_version).toBe('1')
      expect(envelope.service).toBe('api.github.com')
      expect(envelope.hook_path).toBe(registrationId)
      expect(envelope.payload).toEqual({ action: 'push', ref: 'refs/heads/main' })
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('rejects webhook with invalid upstream signature', async () => {
    await seedServiceWithWebhookConfig()

    const registrationId = randomId()
    const encryptedSecret = await encryptCredentials(TEST_ENCRYPTION_KEY, {
      headers: { secret: 'real-secret' },
    })

    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/callback',
      encryptedWebhookSecret: encryptedSecret,
    })

    const res = await req(`/hooks/api.github.com/${registrationId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Hub-Signature-256': 'sha256=0000000000000000000000000000000000000000000000000000000000000000',
      },
      body: '{"action":"push"}',
    })

    expect(res.status).toBe(401)
    const body = (await res.json()) as any
    expect(body.error).toContain('Invalid upstream signature')
  })

  it('forwards webhook without verification when no secret stored', async () => {
    await seedServiceWithWebhookConfig()

    const registrationId = randomId()
    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/callback',
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))

    try {
      const res = await req(`/hooks/api.github.com/${registrationId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"action":"push"}',
      })

      expect(res.status).toBe(200)

      const calls = (globalThis.fetch as any).mock.calls
      const callbackCall = calls.find((c: any) => c[0] === 'https://my-agent.run/callback')
      expect(callbackCall).toBeTruthy()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('Ed25519 signature on forwarded envelope is verifiable via JWKS', async () => {
    await seedServiceWithWebhookConfig()

    const registrationId = randomId()
    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/callback',
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))

    try {
      await req(`/hooks/api.github.com/${registrationId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"test":true}',
      })

      // Get the forwarded envelope and signature
      const calls = (globalThis.fetch as any).mock.calls
      const callbackCall = calls.find((c: any) => c[0] === 'https://my-agent.run/callback')
      const envelopeJson = callbackCall[1].body as string
      const signatureHex = callbackCall[1].headers['Warden-Signature'] as string

      // Get public key from JWKS endpoint
      const jwksRes = await req('/.well-known/jwks.json')
      const jwks = (await jwksRes.json()) as any
      const jwk = jwks.keys[0]

      // Decode base64url x value to get public key bytes
      const xBase64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/')
      const xBinary = atob(xBase64)
      const publicKeyBytes = new Uint8Array(xBinary.length)
      for (let i = 0; i < xBinary.length; i++) {
        publicKeyBytes[i] = xBinary.charCodeAt(i)
      }

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        publicKeyBytes,
        { name: 'Ed25519' },
        false,
        ['verify'],
      )

      const sigBytes = new Uint8Array(signatureHex.length / 2)
      for (let i = 0; i < signatureHex.length; i += 2) {
        sigBytes[i / 2] = parseInt(signatureHex.substring(i, i + 2), 16)
      }

      const valid = await crypto.subtle.verify(
        'Ed25519',
        cryptoKey,
        sigBytes,
        new TextEncoder().encode(envelopeJson),
      )
      expect(valid).toBe(true)
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})

// ─── Proxy Webhook Interception ──────────────────────────────────────────────

describe.skip('Proxy Webhook Interception', () => {
  it('intercepts Warden-Callback header and replaces placeholders', async () => {
    await seedServiceWithCred()

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: 12345 }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const token = mintProxyToken('api.github.com', TEST_ORG_ID)
      const res = await req('/proxy/api.github.com/repos/owner/repo/hooks', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Warden-Callback': 'https://my-agent.run/on-push',
        },
        body: JSON.stringify({
          events: ['push'],
          config: {
            url: '$WARDEN_HOOK_URL',
            secret: '$WARDEN_HOOK_SECRET',
            content_type: 'json',
          },
        }),
      })

      expect(res.status).toBe(201)

      // Verify Warden-Registration-Id header in response
      const registrationId = res.headers.get('Warden-Registration-Id')
      expect(registrationId).toBeTruthy()

      // Verify placeholders were replaced in upstream call
      const calls = (globalThis.fetch as any).mock.calls
      const upstreamCall = calls.find((c: any) =>
        String(c[0]).includes('api.github.com/repos/owner/repo/hooks'),
      )
      expect(upstreamCall).toBeTruthy()

      const upstreamBody = upstreamCall[1].body as string
      expect(upstreamBody).not.toContain('$WARDEN_HOOK_URL')
      expect(upstreamBody).not.toContain('$WARDEN_HOOK_SECRET')
      expect(upstreamBody).toContain('/hooks/api.github.com/')

      // Verify Warden-Callback header was stripped from upstream
      const upstreamHeaders = upstreamCall[1].headers as Headers
      expect(upstreamHeaders.get('warden-callback')).toBeNull()

      // Verify registration was created in DB
      const reg = await getWebhookRegistration(db, 'api.github.com', registrationId!)
      expect(reg).not.toBeNull()
      expect(reg!.callbackUrl).toBe('https://my-agent.run/on-push')
      expect(reg!.orgId).toBe(TEST_ORG_ID)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('extracts secret from response when secretSource is "response"', async () => {
    // Seed service with response-based secret
    await seedServiceWithWebhookConfig('api.stripe.com', {
      signatureHeader: 'Stripe-Signature',
      algorithm: 'hmac-sha256',
      secretSource: 'response',
      secretResponsePath: 'secret',
    })
    await mgmtReq(`/credentials/api.stripe.com?org=${TEST_ORG_ID}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'sk_test_123' }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: 'we_123', secret: 'whsec_server_returned_secret' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const token = mintProxyToken('api.stripe.com', TEST_ORG_ID)
      const res = await req('/proxy/api.stripe.com/v1/webhook_endpoints', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Warden-Callback': 'https://my-agent.run/on-payment',
        },
        body: JSON.stringify({
          url: '$WARDEN_HOOK_URL',
          enabled_events: ['charge.succeeded'],
        }),
      })

      expect(res.status).toBe(200)
      const registrationId = res.headers.get('Warden-Registration-Id')
      expect(registrationId).toBeTruthy()

      // Verify registration was updated with server-returned secret
      const reg = await getWebhookRegistration(db, 'api.stripe.com', registrationId!)
      expect(reg).not.toBeNull()
      expect(reg!.encryptedWebhookSecret).not.toBeNull()
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})

// ─── Registration Management ─────────────────────────────────────────────────

describe.skip('Registration Management', () => {
  it('lists registrations for org', async () => {
    const registrationId = randomId()
    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/callback',
    })

    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req('/hooks/registrations', {
      headers: { Authorization: `Bearer ${token}` },
    })

    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].id).toBe(registrationId)
    expect(body[0].service).toBe('api.github.com')
    expect(body[0].callbackUrl).toBe('https://my-agent.run/callback')
    expect(body[0].hookUrl).toContain(`/hooks/api.github.com/${registrationId}`)
  })

  it('creates registration via POST', async () => {
    await seedServiceWithWebhookConfig()

    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req('/hooks/registrations', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        service: 'api.github.com',
        callbackUrl: 'https://my-agent.run/callback',
        webhookSecret: 'my-secret',
      }),
    })

    expect(res.status).toBe(201)
    const body = (await res.json()) as any
    expect(body.id).toBeTruthy()
    expect(body.hookUrl).toContain(`/hooks/api.github.com/${body.id}`)

    // Verify registration in DB
    const reg = await getWebhookRegistration(db, 'api.github.com', body.id)
    expect(reg).not.toBeNull()
    expect(reg!.callbackUrl).toBe('https://my-agent.run/callback')
  })

  it('rejects registration without required fields', async () => {
    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req('/hooks/registrations', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ service: 'api.github.com' }),
    })

    expect(res.status).toBe(400)
  })

  it('deletes registration', async () => {
    const registrationId = randomId()
    await upsertWebhookRegistration(db, registrationId, {
      orgId: TEST_ORG_ID,
      service: 'api.github.com',
      callbackUrl: 'https://my-agent.run/callback',
    })

    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req(`/hooks/registrations/${registrationId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })

    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.ok).toBe(true)

    // Verify deleted
    const reg = await getWebhookRegistration(db, 'api.github.com', registrationId)
    expect(reg).toBeNull()
  })

  it('returns 404 when deleting non-existent registration', async () => {
    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req('/hooks/registrations/nonexistent', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })

    expect(res.status).toBe(404)
  })

  it('requires auth for management endpoints', async () => {
    const res = await req('/hooks/registrations')
    expect(res.status).toBe(401)
  })
})
