import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createApp } from '../src/managed/app'
import {
  createTestDb,
  BISCUIT_PRIVATE_KEY,
  TEST_SESSION_SECRET,
  TEST_ORG_ID,
  buildTestSessionCookie,
  mintRootToken,
  type TestDb,
} from './setup'
import {
  mintToken,
  restrictToken,
  extractTokenFacts,
  extractUserId,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
  stripPrefix,
  parseTtlSeconds,
  authorizeRequest,
} from '../src/biscuit'
import { extractBearerToken } from '../src/proxy'
import { isDnsError } from '../src/lib/dns'
import {
  revokeToken,
  upsertCredential,
  getCredential,
  deleteCredential,
  isRevoked,
  upsertService,
  listServicesWithCredentialCounts,
  createAuthFlow,
  completeAuthFlow,
  getAuthFlow,
} from '../src/db/queries'
import { encryptCredentials, decryptCredentials, buildCredentialHeaders, deriveEncryptionKey } from '../src/lib/credentials-crypto'

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

async function sessionReq(path: string, init: RequestInit = {}) {
  const cookie = await buildTestSessionCookie()
  return req(path, {
    ...init,
    headers: { Cookie: cookie, ...init.headers },
  })
}

function mgmtReq(path: string, init: RequestInit = {}) {
  const token = mintRootToken()
  return req(path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...init.headers },
  })
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function seedService(slug = 'github') {
  await mgmtReq(`/services/${slug}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      allowedHosts: ['api.github.com'],
      displayName: 'GitHub',
      description: 'REST API for GitHub.',
      authSchemes: [
        { type: 'http', scheme: 'bearer' },
        { type: 'oauth2', authorizeUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', scopes: 'repo read:user' },
      ],
      docsUrl: 'https://docs.github.com/en/rest',
    }),
  })
}

async function seedServiceWithCred(userId = TEST_ORG_ID) {
  await seedService()
  await mgmtReq('/credentials/github', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'Act-As': userId },
    body: JSON.stringify({ token: 'ghp_test123' }),
  })
}

// ─── Root Landing Page ───────────────────────────────────────────────────────

describe('Root Landing Page', () => {
  it('redirects to catalog when no FRONTEND_URL is set', async () => {
    const res = await req('/', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/api/catalog')
  })

})

// ─── Management Auth ─────────────────────────────────────────────────────────

describe('Management Auth', () => {
  it('rejects requests without auth header', async () => {
    const res = await req('/services', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(401)
  })

  it('rejects requests with invalid token', async () => {
    const res = await req('/services/test', {
      method: 'PUT',
      headers: { Authorization: 'Bearer invalid_token', 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedHosts: ['test.api.com'] }),
    })
    expect(res.status).toBe(401)
  })

  it('rejects invalid token on GET /services', async () => {
    const res = await req('/services', {
      headers: { Authorization: 'Bearer invalid_token' },
    })
    expect(res.status).toBe(401)
  })

  it('rejects revoked token on GET /services', async () => {
    const token = mintRootToken()
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(token, publicKey)
    await revokeToken(db, revIds[0], 'test revocation')
    const res = await req('/services', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('revoked')
  })

  it('accepts requests with valid management token', async () => {
    const res = await mgmtReq('/services', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
  })

  it('rejects revoked tokens', async () => {
    const token = mintRootToken()
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(token, publicKey)
    await revokeToken(db, revIds[0], 'test revocation')

    const res = await req('/services/test', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedHosts: ['test.api.com'] }),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('revoked')
  })

  it('rejects token without required right', async () => {
    // Mint token with no rights, try to access services management
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'some-user')
    const res = await req('/services/test', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ allowedHosts: ['test.api.com'] }),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('manage_services')
  })

  it('rejects credential access for wrong user', async () => {
    // Token for "other" user trying to access TEST_ORG_ID's credentials
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'other')
    const res = await req('/credentials', {
      headers: { Authorization: `Bearer ${token}`, 'Act-As': TEST_ORG_ID },
    })
    expect(res.status).toBe(403)
  })

  it('allows admin token to act as another user via Act-As', async () => {
    await seedService()
    await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': 'alice' },
      body: JSON.stringify({ token: 'ghp_admin_seeded' }),
    })

    const res = await mgmtReq('/credentials', {
      headers: { 'Act-As': 'alice' },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].slug).toBe('github')
  })

  it('rejects service-attenuated tokens on management endpoints', async () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const token = restrictToken(base, publicKey, [
      { services: 'github', methods: 'GET' },
    ])

    const res = await req('/credentials', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })

  it('rejects expired attenuated tokens on management endpoints', async () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const token = restrictToken(base, publicKey, [{ ttl: 1 }])
    await sleep(2200)

    const res = await req('/services', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })
})

// ─── Service Management ─────────────────────────────────────────────────────

describe('Service Management', () => {
  it('creates a service', async () => {
    await seedService()
    const res = await mgmtReq('/services')
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].slug).toBe('github')
  })

  it('rejects reserved names', async () => {
    const res = await mgmtReq('/services/vaults', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedHosts: ['vaults.example.com'] }),
    })
    expect(res.status).toBe(400)
  })

  it('rejects service without allowedHosts', async () => {
    const res = await mgmtReq('/services/test', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayName: 'Test' }),
    })
    expect(res.status).toBe(400)
  })

  it('deletes a service', async () => {
    await seedService()
    const res = await mgmtReq('/services/github', { method: 'DELETE' })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/services')
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })

  it('returns 404 when deleting non-existent service', async () => {
    const res = await mgmtReq('/services/nonexistent', { method: 'DELETE' })
    expect(res.status).toBe(404)
  })

  it('lists all services for any authenticated user', async () => {
    await seedService('github')
    await mgmtReq('/services/linear', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedHosts: ['api.linear.app'] }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, 'test-user')
    const res = await req('/services', {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(2)
  })

  it('gets a single service by name', async () => {
    await seedService()
    const res = await mgmtReq('/services/github')
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.slug).toBe('github')
    expect(body.allowedHosts).toContain('api.github.com')
    expect(body.displayName).toBe('GitHub')
    expect(body.authSchemes).toBeInstanceOf(Array)
    expect(body.authSchemes).toHaveLength(2)
  })

  it('returns 404 for non-existent service', async () => {
    const res = await mgmtReq('/services/nonexistent')
    expect(res.status).toBe(404)
  })

  it('gets a service with any authenticated token', async () => {
    await seedService()
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'test-user')
    const res = await req('/services/github', {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.slug).toBe('github')
  })
})

// ─── JWKS Endpoint ──────────────────────────────────────────────────────────

describe('JWKS Endpoint', () => {
  it('returns valid JWK with Ed25519 key', async () => {
    const res = await req('/.well-known/jwks.json')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.keys).toHaveLength(1)
    expect(body.keys[0].kty).toBe('OKP')
    expect(body.keys[0].crv).toBe('Ed25519')
    expect(body.keys[0].use).toBe('sig')
    expect(body.keys[0].kid).toBe('agentpw-ed25519-1')
    expect(body.keys[0].x).toBeDefined()
  })
})

// ─── Credential Management (org-scoped) ────────────────────────────────────

describe('Credential Management', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('stores a credential', async () => {
    const res = await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })
    expect(res.status).toBe(200)
  })

  it('stores credential with expiresAt', async () => {
    const expiresAt = new Date(Date.now() + 86400000).toISOString()
    const res = await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({
        token: 'ghp_test123',
        expiresAt,
      }),
    })
    expect(res.status).toBe(200)
  })

  it('rejects credential without token or headers', async () => {
    const res = await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  it('stores credential with explicit headers map', async () => {
    const res = await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({
        headers: { 'Authorization': 'Bearer ghp_multi', 'X-Org-Id': 'org_123' },
      }),
    })
    expect(res.status).toBe(200)

    const cred = await getCredential(db, TEST_ORG_ID, 'github')
    expect(cred).not.toBeNull()
    const stored = await decryptCredentials(TEST_ENCRYPTION_KEY, cred?.encryptedCredentials)
    expect(stored.headers).toEqual({
      'Authorization': 'Bearer ghp_multi',
      'X-Org-Id': 'org_123',
    })
  })

  it('lists credentials for a user', async () => {
    await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq('/credentials', { headers: { 'Act-As': TEST_ORG_ID } })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].slug).toBe('github')
    expect(body[0].createdAt).toBeDefined()
  })

  it('rejects credential for non-existent service', async () => {
    const res = await mgmtReq('/credentials/nonexistent', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'test' }),
    })
    expect(res.status).toBe(404)
  })

  it('deletes a credential', async () => {
    await mgmtReq('/credentials/github', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq('/credentials/github', {
      method: 'DELETE',
      headers: { 'Act-As': TEST_ORG_ID },
    })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/credentials', { headers: { 'Act-As': TEST_ORG_ID } })
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })

  it('returns 404 when deleting non-existent credential', async () => {
    const res = await mgmtReq('/credentials/nonexistent', {
      method: 'DELETE',
      headers: { 'Act-As': TEST_ORG_ID },
    })
    expect(res.status).toBe(404)
  })
})

// ─── Token Revocation ───────────────────────────────────────────────────────

describe('Token Revocation', () => {
  it('revokes the caller\'s own token', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const res = await req('/tokens/revoke', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason: 'compromised' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.ok).toBe(true)
    expect(body.revokedIds.length).toBeGreaterThan(0)

    // Token is now revoked — subsequent use should fail
    const res2 = await req('/tokens/revoke', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res2.status).toBe(403)
  })

  it('rejects revocation without auth', async () => {
    const res = await req('/tokens/revoke', { method: 'POST' })
    expect(res.status).toBe(401)
  })
})

// ─── Proxy ───────────────────────────────────────────────────────────────────

describe('Proxy', () => {
  it('rejects requests without auth', async () => {
    await seedService()
    const res = await req('/proxy/github/api.github.com/user')
    expect(res.status).toBe(401)
  })

  it('rejects requests with invalid token', async () => {
    await seedService()
    const res = await req('/proxy/github/api.github.com/user', {
      headers: { Authorization: 'Bearer invalid_token' },
    })
    expect(res.status).toBe(401)
  })

  it('returns 404 for unknown service in proxy', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const res = await req('/proxy/unknown/unknown.api.com/path', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
  })

  it('returns 403 for forbidden method via attenuation', async () => {
    await seedService()
    // Token attenuated to allow only GET
    const base = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const token = restrictToken(base, publicKey, [
      { services: 'github', methods: 'GET' },
    ])
    const res = await req('/proxy/github/api.github.com/repos', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })

  it('returns 403 for revoked proxy token', async () => {
    await seedService()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(token, publicKey)
    await revokeToken(db, revIds[0], 'test')

    const res = await req('/proxy/github/api.github.com/user', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })

  it('returns 404 when no credential found for user', async () => {
    await seedService()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)
    const res = await req('/proxy/github/api.github.com/user', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
    const body = (await res.json()) as any
    expect(body.error).toContain('No credential')
  })

  it('proxies request with bearer auth and returns upstream response', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    // Mock fetch for upstream
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ login: 'alice' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await req('/proxy/github/api.github.com/user', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(200)
      const body = (await res.json()) as any
      expect(body.login).toBe('alice')

      // Verify upstream call had correct auth header (filter past any background probe calls)
      const calls = (globalThis.fetch as any).mock.calls
      const fetchCall = calls.find((c: any) => c[0] === 'https://api.github.com/user')
      expect(fetchCall).toBeTruthy()
      const headers = fetchCall[1].headers as Headers
      expect(headers.get('Authorization')).toBe('Bearer ghp_test123')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('does not log injected credential headers', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await req('/proxy/github/api.github.com/user', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(200)

      const logs = logSpy.mock.calls.map(call => String(call[0])).join('\n')
      expect(logs).not.toContain('ghp_test123')
    } finally {
      globalThis.fetch = originalFetch
      logSpy.mockRestore()
    }
  })

  it('proxies with apiKey auth scheme', async () => {
    // Register service with apiKey auth scheme
    await mgmtReq('/services/example', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.example.com'],
        authSchemes: [{ type: 'apiKey', in: 'header', name: 'X-API-Key' }],
      }),
    })
    await mgmtReq('/credentials/example', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'sk_test_key' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('ok', { status: 200 }),
    )

    try {
      const res = await req('/proxy/example/api.example.com/data', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(200)

      const calls = (globalThis.fetch as any).mock.calls
      const fetchCall = calls.find((c: any) => String(c[0]).includes('api.example.com'))
      expect(fetchCall).toBeTruthy()
      const headers = fetchCall[1].headers as Headers
      expect(headers.get('X-API-Key')).toBe('sk_test_key')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('proxies with basic auth scheme', async () => {
    await mgmtReq('/services/basic', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.basic.com'],
        authSchemes: [{ type: 'http', scheme: 'basic' }],
      }),
    })
    await mgmtReq('/credentials/basic', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'user:pass' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('ok', { status: 200 }),
    )

    try {
      const res = await req('/proxy/basic/api.basic.com/data', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(200)

      const calls = (globalThis.fetch as any).mock.calls
      const fetchCall = calls.find((c: any) => String(c[0]).includes('api.basic.com'))
      expect(fetchCall).toBeTruthy()
      const headers = fetchCall[1].headers as Headers
      expect(headers.get('Authorization')).toBe(`Basic ${btoa('user:pass')}`)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('forwards POST body to upstream', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('created', { status: 201 }),
    )

    try {
      const res = await req('/proxy/github/api.github.com/repos', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'test-repo' }),
      })
      expect(res.status).toBe(201)

      // Find the proxy call (POST to upstream), ignoring any background probe calls
      const calls = (globalThis.fetch as any).mock.calls
      const proxyCall = calls.find((c: any) => c[1]?.method === 'POST')
      expect(proxyCall).toBeTruthy()
      expect(proxyCall[1].body).toBeTruthy()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('returns 502 with DNS hint when upstream does not resolve', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'))
    try {
      const res = await req('/proxy/github/api.github.com/user', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(502)
      const body = (await res.json()) as any
      expect(body.error).toContain('DNS resolution failed')
      expect(body.hint).toBeDefined()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('returns 502 for non-DNS upstream failures', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockRejectedValue(
      new Error('connect ECONNREFUSED 1.2.3.4:443'),
    )
    try {
      const res = await req('/proxy/github/api.github.com/user', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(502)
      const body = (await res.json()) as any
      expect(body.error).toContain('Failed to reach upstream')
      expect(body.hint).toBeDefined()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('returns 404 for reserved paths in proxy', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'test-user')
    const res = await req('/tokens/something', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
  })
})

// ─── Auth Flow Polling ──────────────────────────────────────────────────────

describe('Auth Flow Polling', () => {
  it('requires a browser session', async () => {
    const res = await req('/auth/status/nonexistent')
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/auth/login')
  })

  it('returns 404 for unknown flow with session', async () => {
    const res = await sessionReq('/auth/status/nonexistent')
    expect(res.status).toBe(404)
  })

  it('returns pending status for active flow', async () => {
    await createAuthFlow(db, {
      id: 'test-flow-1',
      slug: 'github',
      method: 'api_key',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const res = await sessionReq('/auth/status/test-flow-1')
    expect(res.status).toBe(202)
    const body = (await res.json()) as any
    expect(body.status).toBe('pending')
  })

  it('returns completed status with token', async () => {
    await createAuthFlow(db, {
      id: 'test-flow-2',
      slug: 'github',
      method: 'api_key',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })
    await completeAuthFlow(db, 'test-flow-2', {
      token: 'apw_test',
      identity: 'alice',
      orgId: TEST_ORG_ID,
    })

    const res = await sessionReq('/auth/status/test-flow-2')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.status).toBe('completed')
    expect(body.token).toBe('apw_test')
    expect(body.identity).toBe('alice')
  })

  it('returns 404 for expired flow', async () => {
    await createAuthFlow(db, {
      id: 'test-flow-expired',
      slug: 'github',
      method: 'api_key',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() - 1000), // already expired
    })

    const res = await sessionReq('/auth/status/test-flow-expired')
    expect(res.status).toBe(404)
  })

  it('forbids polling a flow for another org', async () => {
    await createAuthFlow(db, {
      id: 'test-flow-other-org',
      slug: 'github',
      method: 'api_key',
      orgId: 'org_other',
      expiresAt: new Date(Date.now() + 600000),
    })

    const res = await sessionReq('/auth/status/test-flow-other-org')
    expect(res.status).toBe(403)
  })
})

// ─── API Key Flow ───────────────────────────────────────────────────────────

describe('API Key Flow', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('redirects to frontend API key form', async () => {
    const res = await sessionReq('/auth/github/api-key', { redirect: 'manual' })
    expect(res.status).toBe(302)
    const location = res.headers.get('Location')!
    expect(location).toContain('/api-key?service=github')
    expect(location).toContain('flow_id=')
  })

  it('redirects to error for unknown service on form', async () => {
    const res = await sessionReq('/auth/unknown/api-key', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/error?message=')
  })

  it('submits API key and stores credential', async () => {
    // First get the form to create a flow
    const formRes = await sessionReq('/auth/github/api-key?flow_id=ak-flow-1-padding-to-32-chars-xx', { redirect: 'manual' })
    expect(formRes.status).toBe(302)

    // Mock fetch so the base URL validation passes
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    try {
      // Submit the API key
      const res = await sessionReq('/auth/github/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=ghp_testkey&flow_id=ak-flow-1-padding-to-32-chars-xx',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      const location = res.headers.get('Location')!
      expect(location).toContain('/success?token=')
      expect(location).toContain('apw_')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('redirects to error for empty API key', async () => {
    const res = await sessionReq('/auth/github/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=&flow_id=ak-flow-2-padding-to-32-chars-xx',
      redirect: 'manual',
    })
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/error?message=')
  })

  it('redirects to error for unknown service on submit', async () => {
    const res = await sessionReq('/auth/unknown/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=test123',
      redirect: 'manual',
    })
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/error?message=')
  })

  it('uses existing flow and does not re-create it', async () => {
    // Create a flow via form visit
    await sessionReq('/auth/github/api-key?flow_id=ak-existing-pad-to-32-chars-xxxx', { redirect: 'manual' })
    // Visit again with same flow_id
    const res = await sessionReq('/auth/github/api-key?flow_id=ak-existing-pad-to-32-chars-xxxx', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('/api-key?service=github')
  })

  it('submits API key without flow_id', async () => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    try {
      const res = await sessionReq('/auth/github/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=ghp_noflow',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key via identity_url (bearer auth)', async () => {
    // Register service with identity_url in authConfig
    await mgmtReq('/services/validated', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['validated.api'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        authConfig: {
          identity_url: 'https://validated.api/whoami',
          identity_path: 'user.login',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: { login: 'carol' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await sessionReq('/auth/validated/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test_key_123',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      const location = res.headers.get('Location')!
      expect(location).toContain('/success?token=')
      expect(location).toContain('apw_')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('redirects to error when identity_url returns error', async () => {
    await mgmtReq('/services/rejected', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['rejected.api'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        authConfig: {
          identity_url: 'https://rejected.api/whoami',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('Unauthorized', { status: 401 }),
    )

    try {
      const res = await sessionReq('/auth/rejected/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=bad_key',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/error?message=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with api_key auth method', async () => {
    await mgmtReq('/services/apikey-svc', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['apikey-svc.api'],
        authSchemes: [{ type: 'apiKey', in: 'header', name: 'X-API-Key' }],
        authConfig: {
          identity_url: 'https://apikey-svc.api/me',
          identity_path: 'name',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ name: 'dave' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await sessionReq('/auth/apikey-svc/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=sk_test',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with basic auth method', async () => {
    await mgmtReq('/services/basic-svc', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['basic-svc.api'],
        authSchemes: [{ type: 'http', scheme: 'basic' }],
        authConfig: {
          identity_url: 'https://basic-svc.api/me',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    )

    try {
      const res = await sessionReq('/auth/basic-svc/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=user:pass',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with POST identity method', async () => {
    await mgmtReq('/services/post-id', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['post-id.api'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        authConfig: {
          identity_url: 'https://post-id.api/verify',
          identity_method: 'POST',
          identity_body: '{"check":true}',
          identity_path: 'id',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: 'eve' }), { status: 200 }),
    )

    try {
      const res = await sessionReq('/auth/post-id/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test123',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles identity validation failure gracefully', async () => {
    await mgmtReq('/services/fail-id', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['fail-id.api'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        authConfig: {
          identity_url: 'https://fail-id.api/whoami',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

    try {
      // Should succeed with default identity despite validation failure
      const res = await sessionReq('/auth/fail-id/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test123',
        redirect: 'manual',
      })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  // ─── Programmatic (JSON) API Key Submission ──────────────────────────────

  it('accepts JSON POST with api_key and flow_id in query', async () => {
    // Create a flow first
    await sessionReq('/auth/github/api-key?flow_id=json-flow-1-pad-to-32-chars-xxxx')

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    try {
      const res = await sessionReq('/auth/github/api-key?flow_id=json-flow-1-pad-to-32-chars-xxxx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'ghp_jsonkey' }),
      })
      expect(res.status).toBe(200)
      const body = (await res.json()) as any
      expect(body.token).toMatch(/^apw_/)
      expect(body.identity).toBe('default')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('accepts JSON POST with flow_id in body', async () => {
    await sessionReq('/auth/github/api-key?flow_id=json-flow-2-pad-to-32-chars-xxxx')

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    try {
      const res = await sessionReq('/auth/github/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'ghp_jsonkey2', flow_id: 'json-flow-2-pad-to-32-chars-xxxx' }),
      })
      expect(res.status).toBe(200)
      const body = (await res.json()) as any
      expect(body.token).toMatch(/^apw_/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('completes flow so polling returns token (JSON path)', async () => {
    await sessionReq('/auth/github/api-key?flow_id=json-poll-1-pad-to-32-chars-xxxx')

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))
    try {
      await sessionReq('/auth/github/api-key?flow_id=json-poll-1-pad-to-32-chars-xxxx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'ghp_pollkey' }),
      })
    } finally {
      globalThis.fetch = originalFetch
    }

    const poll = await sessionReq('/auth/status/json-poll-1-pad-to-32-chars-xxxx')
    expect(poll.status).toBe(200)
    const body = (await poll.json()) as any
    expect(body.status).toBe('completed')
    expect(body.token).toMatch(/^apw_/)
  })

  it('rejects JSON POST with missing api_key', async () => {
    const res = await sessionReq('/auth/github/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
    const body = (await res.json()) as any
    expect(body.error).toContain('api_key')
  })

  it('returns JSON 404 for unknown service', async () => {
    const res = await sessionReq('/auth/unknown/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'test' }),
    })
    expect(res.status).toBe(404)
    const body = (await res.json()) as any
    expect(body.error).toContain('unknown')
  })

  it('rejects JSON POST when identity_url returns error', async () => {
    await mgmtReq('/services/json-rejected', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['json-rejected.api'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        authConfig: {
          identity_url: 'https://json-rejected.api/whoami',
        },
      }),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('Unauthorized', { status: 401 }),
    )

    try {
      const res = await sessionReq('/auth/json-rejected/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'bad_key' }),
      })
      expect(res.status).toBe(400)
      const body = (await res.json()) as any
      expect(body.error).toContain('rejected')
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})

// ─── E2E: Agent with Invalid API ────────────────────────────────────────────

describe('E2E: agent with invalid API', () => {
  it('rejects API key when upstream returns 401', async () => {
    await mgmtReq('/services/betterstack', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['telemetry.betterstack.com'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
      }),
    })

    // Agent submits an invalid API key — upstream returns 401
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('{"errors":"Invalid Team API token"}', { status: 401 }),
    )
    try {
      const submit = await sessionReq('/auth/betterstack/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'bad_token_123' }),
      })
      expect(submit.status).toBe(400)
      const body = (await submit.json()) as any
      expect(body.error).toContain('rejected')
      expect(body.hint).toContain('401')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('returns 502 with DNS hint when proxying to unreachable upstream', async () => {
    // Register a service, then simulate DNS failure on proxy
    await mgmtReq('/services/fake-api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ allowedHosts: ['fake-api.nonexistent.test'] }),
    })

    // Store a credential for this service
    await mgmtReq('/credentials/fake-api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Act-As': TEST_ORG_ID },
      body: JSON.stringify({ token: 'test_token' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, TEST_ORG_ID)

    // Simulate DNS failure when proxying
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'))
    try {
      const res = await req('/proxy/fake-api/fake-api.nonexistent.test/api/v1/data', {
        headers: { Authorization: `Bearer ${token}` },
      })
      expect(res.status).toBe(502)
      const body = (await res.json()) as any
      expect(body.error).toContain('DNS resolution failed')
      expect(body.hint).toBeDefined()
    } finally {
      globalThis.fetch = originalFetch
    }
  })

})

// ─── OAuth Flow ─────────────────────────────────────────────────────────────

describe('OAuth Flow', () => {
  beforeEach(async () => {
    // Register a service with OAuth configured
    await mgmtReq('/services/github-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.github.com'],
        oauthClientId: 'test_client_id',
        oauthClientSecret: 'test_client_secret',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', scopes: 'repo user' },
        ],
      }),
    })
  })

  it('redirects to OAuth provider', async () => {
    const res = await sessionReq('/auth/github-oauth/oauth', {
      redirect: 'manual',
    })
    expect(res.status).toBe(302)
    const location = res.headers.get('Location')!
    expect(location).toContain('github.com/login/oauth/authorize')
    expect(location).toContain('client_id=test_client_id')
    expect(location).toContain('scope=repo+user')
    expect(location).toContain('code_challenge_method=S256')
  })

  it('returns 404 for unknown service in OAuth start', async () => {
    const res = await sessionReq('/auth/unknown/oauth', { redirect: 'manual' })
    expect(res.status).toBe(404)
  })

  it('returns 400 for service without OAuth config', async () => {
    await seedService() // GitHub without OAuth config
    const res = await sessionReq('/auth/github/oauth', { redirect: 'manual' })
    expect(res.status).toBe(400)
  })

  it('handles OAuth callback error param', async () => {
    const res = await req('/auth/github-oauth/oauth/callback?error=access_denied', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('access_denied')
  })

  it('rejects callback without code or state', async () => {
    const res = await req('/auth/github-oauth/oauth/callback', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('Missing code or state')
  })

  it('rejects callback with unknown flow state', async () => {
    const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=unknown', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('Unknown or expired')
  })

  it('rejects callback for expired flow', async () => {
    await createAuthFlow(db, {
      id: 'expired-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test',
      expiresAt: new Date(Date.now() - 1000),
    })

    const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=expired-flow', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('expired')
  })

  it('rejects callback for already completed flow', async () => {
    await createAuthFlow(db, {
      id: 'completed-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test',
      expiresAt: new Date(Date.now() + 600000),
    })
    await completeAuthFlow(db, 'completed-flow', {
      token: 'apw_old',
      identity: 'alice',
      orgId: TEST_ORG_ID,
    })

    const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=completed-flow', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('already completed')
  })

  it('handles failed token exchange', async () => {
    await createAuthFlow(db, {
      id: 'token-fail-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('Bad Request', { status: 400 }),
    )

    try {
      const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=token-fail-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(decodeURIComponent(res.headers.get('Location')!)).toContain('Token exchange failed')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles missing access token in response', async () => {
    await createAuthFlow(db, {
      id: 'no-token-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'no token' }), { status: 200 }),
    )

    try {
      const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=no-token-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(decodeURIComponent(res.headers.get('Location')!)).toContain('No access token')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('completes successful OAuth flow', async () => {
    await createAuthFlow(db, {
      id: 'success-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ access_token: 'gho_test_token' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await req('/auth/github-oauth/oauth/callback?code=abc&state=success-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      const location = res.headers.get('Location')!
      expect(location).toContain('/success?token=')
      expect(location).toContain('apw_')

      // Verify flow was completed
      const flow = await getAuthFlow(db, 'success-flow')
      expect(flow?.status).toBe('completed')
      expect(flow?.token).toMatch(/^apw_/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('resolves identity via whoami after token exchange', async () => {
    // Register service with identity_url in authConfig
    await mgmtReq('/services/id-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.id-oauth.com'],
        oauthClientId: 'cid',
        oauthClientSecret: 'csecret',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://id-oauth.com/authorize', tokenUrl: 'https://id-oauth.com/token' },
        ],
        authConfig: {
          identity_url: 'https://api.id-oauth.com/me',
          identity_path: 'user.email',
        },
      }),
    })
    await createAuthFlow(db, {
      id: 'id-flow',
      slug: 'id-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    let callCount = 0
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++
      if (callCount === 1) {
        // Token exchange
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'gho_token' }), { status: 200 }),
        )
      }
      // Identity resolution
      return Promise.resolve(
        new Response(JSON.stringify({ user: { email: 'carol@example.com' } }), { status: 200 }),
      )
    })

    try {
      const res = await req('/auth/id-oauth/oauth/callback?code=abc&state=id-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)

      const flow = await getAuthFlow(db, 'id-flow')
      expect(flow?.identity).toBe('carol@example.com')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('resolves identity via POST method', async () => {
    await mgmtReq('/services/post-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.post-oauth.com'],
        oauthClientId: 'cid',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://post-oauth.com/authorize', tokenUrl: 'https://post-oauth.com/token' },
        ],
        authConfig: {
          identity_url: 'https://api.post-oauth.com/verify',
          identity_method: 'POST',
          identity_body: '{"q":"me"}',
          identity_path: 'name',
        },
      }),
    })
    await createAuthFlow(db, {
      id: 'post-id-flow',
      slug: 'post-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    let callCount = 0
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++
      if (callCount === 1) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'token' }), { status: 200 }),
        )
      }
      return Promise.resolve(
        new Response(JSON.stringify({ name: 'frank' }), { status: 200 }),
      )
    })

    try {
      const res = await req('/auth/post-oauth/oauth/callback?code=abc&state=post-id-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      const flow = await getAuthFlow(db, 'post-id-flow')
      expect(flow?.identity).toBe('frank')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('falls back to default identity when whoami fails', async () => {
    await mgmtReq('/services/fail-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.fail-oauth.com'],
        oauthClientId: 'cid',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://fail-oauth.com/authorize', tokenUrl: 'https://fail-oauth.com/token' },
        ],
        authConfig: {
          identity_url: 'https://api.fail-oauth.com/me',
        },
      }),
    })
    await createAuthFlow(db, {
      id: 'fail-id-flow',
      slug: 'fail-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    let callCount = 0
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++
      if (callCount === 1) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'token' }), { status: 200 }),
        )
      }
      return Promise.reject(new Error('Network error'))
    })

    try {
      const res = await req('/auth/fail-oauth/oauth/callback?code=abc&state=fail-id-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      const flow = await getAuthFlow(db, 'fail-id-flow')
      expect(flow?.identity).toBe('default')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('falls back to default identity when identity_url set but no identity_path', async () => {
    await mgmtReq('/services/nopath-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.nopath-oauth.com'],
        oauthClientId: 'cid',
        oauthClientSecret: 'csecret',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://nopath-oauth.com/authorize', tokenUrl: 'https://nopath-oauth.com/token' },
        ],
        authConfig: {
          identity_url: 'https://api.nopath-oauth.com/me',
          // no identity_path
        },
      }),
    })
    await createAuthFlow(db, {
      id: 'nopath-flow',
      slug: 'nopath-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    let callCount = 0
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++
      if (callCount === 1) {
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: 'tok' }), { status: 200 }),
        )
      }
      // Identity endpoint returns OK but no identity_path to extract from
      return Promise.resolve(
        new Response(JSON.stringify({ id: 123, name: 'bob' }), { status: 200 }),
      )
    })

    try {
      const res = await req('/auth/nopath-oauth/oauth/callback?code=abc&state=nopath-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      const flow = await getAuthFlow(db, 'nopath-flow')
      expect(flow?.identity).toBe('default')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles token exchange with custom token_path and token_accept', async () => {
    await mgmtReq('/services/custom-oauth', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['api.custom-oauth.com'],
        oauthClientId: 'cid',
        oauthClientSecret: 'csecret',
        authSchemes: [
          { type: 'http', scheme: 'bearer' },
          { type: 'oauth2', authorizeUrl: 'https://custom-oauth.com/authorize', tokenUrl: 'https://custom-oauth.com/token' },
        ],
        authConfig: {
          token_path: 'data.token',
          token_accept: 'application/json',
        },
      }),
    })
    await createAuthFlow(db, {
      id: 'custom-token-flow',
      slug: 'custom-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { token: 'custom_access_token' } }), { status: 200 }),
    )

    try {
      const res = await req('/auth/custom-oauth/oauth/callback?code=abc&state=custom-token-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('uses session orgId when flow has no orgId', async () => {
    await createAuthFlow(db, {
      id: 'no-org-flow',
      slug: 'github-oauth',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ access_token: 'token' }), { status: 200 }),
    )

    try {
      const res = await sessionReq('/auth/github-oauth/oauth/callback?code=abc&state=no-org-flow', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toContain('/success?token=')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('rejects callback for service with missing OAuth token config', async () => {
    // Register service without oauth2 scheme (no tokenUrl)
    await mgmtReq('/services/no-token-url', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowedHosts: ['no-token-url.com'],
        oauthClientId: 'cid',
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        // Note: no oauth2 scheme
      }),
    })
    await createAuthFlow(db, {
      id: 'no-token-url-flow',
      slug: 'no-token-url',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const res = await req('/auth/no-token-url/oauth/callback?code=abc&state=no-token-url-flow', { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(decodeURIComponent(res.headers.get('Location')!)).toContain('OAuth not configured')
  })
})

// ─── Biscuit Functions ──────────────────────────────────────────────────────

describe('Biscuit Functions', () => {
  const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)

  it('strips apw_ prefix', () => {
    expect(stripPrefix('apw_abc')).toBe('abc')
  })

  it('returns token as-is without prefix', () => {
    expect(stripPrefix('abc')).toBe('abc')
  })

  it('parseTtlSeconds handles number input', () => {
    expect(parseTtlSeconds(3600)).toBe(3600)
  })

  it('parseTtlSeconds handles numeric string', () => {
    expect(parseTtlSeconds('300')).toBe(300)
  })

  it('parseTtlSeconds handles s/m/h/d units', () => {
    expect(parseTtlSeconds('30s')).toBe(30)
    expect(parseTtlSeconds('5m')).toBe(300)
    expect(parseTtlSeconds('2h')).toBe(7200)
    expect(parseTtlSeconds('1d')).toBe(86400)
  })

  it('parseTtlSeconds throws on invalid format', () => {
    expect(() => parseTtlSeconds('abc')).toThrow('Invalid TTL format')
  })

  it('mints token with user identity', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    expect(token).toMatch(/^apw_/)
    const userId = extractUserId(token, publicKey)
    expect(userId).toBe('alice')
  })

  it('mints token with rights', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'admin-user', ['admin', 'manage_services'])
    const facts = extractTokenFacts(token, publicKey)
    expect(facts.userId).toBe('admin-user')
    expect(facts.rights).toContain('admin')
    expect(facts.rights).toContain('manage_services')
  })

  it('extractUserId returns null for invalid token', () => {
    const userId = extractUserId('invalid', publicKey)
    expect(userId).toBeNull()
  })

  it('extractTokenFacts returns empty for invalid token', () => {
    const facts = extractTokenFacts('invalid', publicKey)
    expect(facts.rights).toEqual([])
    expect(facts.userId).toBeNull()
  })

  it('authorizeRequest returns authorized for valid user token', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    const result = authorizeRequest(token, publicKey, 'github', 'GET', '/user')
    expect(result.authorized).toBe(true)
  })

  it('authorizeRequest returns authorized for admin token', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'root', ['admin'])
    const result = authorizeRequest(token, publicKey, 'github', 'POST', '/repos')
    expect(result.authorized).toBe(true)
  })

  it('authorizeRequest returns forbidden for attenuated method mismatch', () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    const token = restrictToken(base, publicKey, [
      { services: 'github', methods: 'GET' },
    ])
    const result = authorizeRequest(token, publicKey, 'github', 'POST', '/user')
    expect(result.authorized).toBe(false)
    expect(result.error).toBeTruthy()
  })

  it('restrictToken with multiple alternatives', () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    const restricted = restrictToken(base, publicKey, [
      { services: 'github', methods: 'GET' },
      { services: 'linear', methods: 'POST' },
    ])
    expect(restricted).toMatch(/^apw_/)
    expect(restricted).not.toBe(base)
  })

  it('restrictToken with TTL constraint', () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    const restricted = restrictToken(base, publicKey, [
      { methods: 'GET', ttl: '1h' },
    ])
    expect(restricted).toMatch(/^apw_/)
  })

  it('restrictToken with path constraint', () => {
    const base = mintToken(BISCUIT_PRIVATE_KEY, 'alice')
    const restricted = restrictToken(base, publicKey, [
      { paths: ['/user', '/repos'] },
    ])
    expect(restricted).toMatch(/^apw_/)
  })

  it('generateKeyPairHex returns valid keys', () => {
    const kp = generateKeyPairHex()
    expect(kp.privateKey).toBeTruthy()
    expect(kp.publicKey).toBeTruthy()
  })
})

// ─── Proxy Helper Functions ─────────────────────────────────────────────────

describe('extractBearerToken', () => {
  it('returns null for undefined header', () => {
    expect(extractBearerToken(undefined)).toBeNull()
  })

  it('strips Bearer prefix', () => {
    expect(extractBearerToken('Bearer abc')).toBe('abc')
  })

  it('returns token without Bearer prefix', () => {
    expect(extractBearerToken('abc')).toBe('abc')
  })
})

// ─── DNS Helpers ─────────────────────────────────────────────────────────────

describe('isDnsError', () => {
  it('detects getaddrinfo ENOTFOUND', () => {
    expect(isDnsError(new Error('getaddrinfo ENOTFOUND api.example.com'))).toBe(true)
  })

  it('detects TypeError fetch failed (CF Workers)', () => {
    expect(isDnsError(new TypeError('fetch failed'))).toBe(true)
  })

  it('does not match connection refused', () => {
    expect(isDnsError(new Error('connect ECONNREFUSED 1.2.3.4:443'))).toBe(false)
  })

  it('does not match non-Error values', () => {
    expect(isDnsError('some string')).toBe(false)
    expect(isDnsError(null)).toBe(false)
  })
})

// ─── Query Functions ────────────────────────────────────────────────────────

describe('Query Functions', () => {
  it('isRevoked returns false for unknown id', async () => {
    expect(await isRevoked(db, 'nonexistent')).toBe(false)
  })

  it('isRevoked returns true after revoking', async () => {
    await revokeToken(db, 'test-rev-id', 'test')
    expect(await isRevoked(db, 'test-rev-id')).toBe(true)
  })

  it('revokeToken is idempotent', async () => {
    await revokeToken(db, 'dup-rev', 'first')
    await revokeToken(db, 'dup-rev', 'second') // should not throw
    expect(await isRevoked(db, 'dup-rev')).toBe(true)
  })

  it('getCredential returns null when not found', async () => {
    const cred = await getCredential(db, 'nonexistent', 'nonexistent')
    expect(cred).toBeNull()
  })

  it('deleteCredential returns false when not found', async () => {
    const deleted = await deleteCredential(db, 'nonexistent', 'nonexistent')
    expect(deleted).toBe(false)
  })

  it('upsertCredential updates existing credential', async () => {
    await upsertService(db, 'test', { allowedHosts: 'test.api' })
    const enc1 = await encryptCredentials(TEST_ENCRYPTION_KEY, { headers: { Authorization: 'Bearer token1' } })
    const enc2 = await encryptCredentials(TEST_ENCRYPTION_KEY, { headers: { Authorization: 'Bearer token2' } })
    await upsertCredential(db, TEST_ORG_ID, 'test', 'default', enc1)
    await upsertCredential(db, TEST_ORG_ID, 'test', 'default', enc2)
    const cred = await getCredential(db, TEST_ORG_ID, 'test')
    const stored = await decryptCredentials(TEST_ENCRYPTION_KEY, cred?.encryptedCredentials)
    expect(stored.headers.Authorization).toBe('Bearer token2')
  })

  it('listServicesWithCredentialCounts returns per-service popularity', async () => {
    await upsertService(db, 'one', { allowedHosts: 'api.one.test' })
    await upsertService(db, 'two', { allowedHosts: 'api.two.test' })

    const encrypted = await encryptCredentials(TEST_ENCRYPTION_KEY, {
      headers: { Authorization: 'Bearer shared-token' },
    })
    await upsertCredential(db, 'personal', 'one', 'alice', encrypted)
    await upsertCredential(db, 'team-alpha', 'one', 'bob', encrypted)

    const rows = await listServicesWithCredentialCounts(db)
    const serviceOne = rows.find(row => row.slug === 'one')
    const serviceTwo = rows.find(row => row.slug === 'two')

    expect(serviceOne?.credentialCount).toBe(2)
    expect(serviceTwo?.credentialCount).toBe(0)
  })

  it('createAuthFlow stores and retrieves a flow', async () => {
    await createAuthFlow(db, {
      id: 'oauth-flow',
      slug: 'github',
      method: 'oauth',
      codeVerifier: 'pkce-verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 60_000),
    })

    const flow = await getAuthFlow(db, 'oauth-flow')
    expect(flow).not.toBeNull()
    expect(flow!.method).toBe('oauth')
    expect(flow!.codeVerifier).toBe('pkce-verifier')
    expect(flow!.orgId).toBe(TEST_ORG_ID)
  })
})

// ─── Credentials Crypto ─────────────────────────────────────────────────────

describe('Credentials Crypto', () => {
  it('encrypts and decrypts credentials round-trip', async () => {
    const creds = { headers: { Authorization: 'Bearer test', 'X-Custom': 'val' } }
    const encrypted = await encryptCredentials(TEST_ENCRYPTION_KEY, creds)
    const decrypted = await decryptCredentials(TEST_ENCRYPTION_KEY, encrypted)
    expect(decrypted).toEqual(creds)
  })

  it('rejects invalid encryption key length', async () => {
    const shortKey = Buffer.from('too-short').toString('base64')
    await expect(
      encryptCredentials(shortKey, { headers: { a: 'b' } }),
    ).rejects.toThrow('Encryption key must be 32 bytes')
  })

  it('rejects truncated ciphertext', async () => {
    await expect(
      decryptCredentials(TEST_ENCRYPTION_KEY, Buffer.alloc(10)),
    ).rejects.toThrow('Invalid ciphertext')
  })

  it('buildCredentialHeaders derives bearer header', () => {
    expect(buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, 'tok123')).toEqual({ Authorization: 'Bearer tok123' })
  })

  it('buildCredentialHeaders derives apiKey header', () => {
    expect(buildCredentialHeaders({ type: 'apiKey', in: 'header', name: 'X-API-Key' }, 'sk_123')).toEqual({ 'X-API-Key': 'sk_123' })
  })

  it('buildCredentialHeaders derives basic header', () => {
    expect(buildCredentialHeaders({ type: 'http', scheme: 'basic' }, 'user:pass')).toEqual({ Authorization: `Basic ${btoa('user:pass')}` })
  })

  it('buildCredentialHeaders derives oauth2 header', () => {
    expect(buildCredentialHeaders({ type: 'oauth2', authorizeUrl: '', tokenUrl: '' }, 'tok')).toEqual({ Authorization: 'Bearer tok' })
  })
})
