import { describe, it, expect, beforeEach, vi } from 'vitest'
import { sql } from 'drizzle-orm'
import { createApp } from '../src/index'
import {
  createTestDb,
  createTestRedis,
  BISCUIT_PRIVATE_KEY,
  TEST_SESSION_SECRET,
  TEST_ORG_ID,
  buildTestSessionCookie,
  mintRootToken,
  mintProxyToken,
  type TestDb,
} from './setup'
import {
  mintToken,
  mintManagementToken,
  restrictToken,
  extractIdentityFromToken,
  extractGrants,
  extractVaultFromToken,
  extractManagementRights,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
  stripPrefix,
  parseTtlSeconds,
  authorizeRequest,
} from '../src/biscuit'
import { extractBearerToken } from '../src/proxy'
import { buildUnauthDiscovery, buildAuthDiscovery, wantsJson } from '../src/discovery'
import {
  revokeToken,
  upsertCredential,
  getCredential,
  deleteCredential,
  isRevoked,
  upsertService,
  getService,
  getOAuthApp,
  upsertOAuthApp,
  getDocPage,
  upsertDocPage,
  listDocPages,
  listSkeletonPages,
  listStaleDocPages,
  deleteDocPages,
  listServicesWithCredentialCounts,
  countCredentialsForService,
} from '../src/db/queries'
import { createAuthFlow, completeAuthFlow, getAuthFlow } from '../src/lib/auth-flow-store'
import { encryptCredentials, decryptCredentials, buildCredentialHeaders } from '../src/lib/credentials-crypto'
import { runDeterministicDiscovery } from '../src/discovery/deterministic'
import type { ProbeResult } from '../src/discovery/types'

// 32-byte base64 key for test encryption
const TEST_ENCRYPTION_KEY = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64')

let db: TestDb
let redis: ReturnType<typeof createTestRedis>
let app: ReturnType<typeof createApp>

beforeEach(async () => {
  db = await createTestDb()
  redis = createTestRedis()
  app = createApp({ db, redis, biscuitPrivateKey: BISCUIT_PRIVATE_KEY, encryptionKey: TEST_ENCRYPTION_KEY, workosCookiePassword: TEST_SESSION_SECRET })
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

async function seedService(service = 'api.github.com') {
  await mgmtReq(`/services/${service}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseUrl: 'https://api.github.com',
      displayName: 'GitHub',
      description: 'REST API for GitHub.',
      authSchemes: [
        { type: 'http', scheme: 'bearer' },
        { type: 'oauth2', authorizeUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', scopes: 'repo read:user' },
      ],
      apiType: 'rest',
      docsUrl: 'https://docs.github.com/en/rest',
    }),
  })
}

async function seedServiceWithCred(orgId = TEST_ORG_ID) {
  await seedService()
  await mgmtReq(`/vaults/${orgId}/credentials/api.github.com`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'ghp_test123' }),
  })
}

// ─── Root Landing Page ───────────────────────────────────────────────────────

describe('Root Landing Page', () => {
  it('returns HTML landing page for browsers', async () => {
    const res = await req('/')
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('Warden')
    expect(text).toContain('One URL between your agents and every API')
  })

  it('returns JSON agent guide for curl-style Accept: */*', async () => {
    const res = await req('/', { headers: { Accept: '*/*' } })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/json')
    const body = (await res.json()) as any
    expect(body.service).toBe('warden')
    expect(body.routes).toBeDefined()
    expect(body.quick_start).toBeDefined()
  })

  it('returns JSON agent guide for Accept: application/json', async () => {
    const res = await req('/', { headers: { Accept: 'application/json' } })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.service).toBe('warden')
    expect(body.quick_start).toBeDefined()
    expect(body.routes).toBeDefined()
    expect(body.routes.discovery.method).toBe('GET')
    expect(body.routes.proxy.path).toBe('/{hostname}/{path}')
    expect(body.example_flow.steps).toHaveLength(3)
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
    const res = await req('/services/test.api.com', {
      method: 'PUT',
      headers: { Authorization: 'Bearer invalid_token', 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: 'https://test.api.com' }),
    })
    expect(res.status).toBe(401)
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

    const res = await req('/services/test.api.com', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: 'https://test.api.com' }),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('revoked')
  })

  it('rejects token without required right', async () => {
    // Mint token with only manage_vaults, try to access services management
    const token = mintManagementToken(BISCUIT_PRIVATE_KEY, ['manage_vaults'], ['*'])
    const res = await req('/services/test.api.com', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ baseUrl: 'https://test.api.com' }),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('manage_services')
  })

  it('rejects vault admin access without vault_admin right', async () => {
    // Token with vault_admin for "other" but not TEST_ORG_ID
    const token = mintManagementToken(BISCUIT_PRIVATE_KEY, ['manage_vaults'], ['other'])
    const res = await req(`/vaults/${TEST_ORG_ID}/credentials`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as any
    expect(body.error).toContain('vault_admin')
  })
})

// ─── Service Management ─────────────────────────────────────────────────────

describe('Service Management', () => {
  it('creates a service', async () => {
    await seedService()
    const res = await mgmtReq('/services')
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].service).toBe('api.github.com')
  })

  it('rejects reserved names', async () => {
    const res = await mgmtReq('/services/vaults', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: 'https://vaults.example.com' }),
    })
    expect(res.status).toBe(400)
  })

  it('rejects service without baseUrl', async () => {
    const res = await mgmtReq('/services/test.api.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ displayName: 'Test' }),
    })
    expect(res.status).toBe(400)
  })

  it('infers icon preview for newly created services', async () => {
    const putRes = await mgmtReq('/services/api.linear.app', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.linear.app',
        displayName: 'Linear',
      }),
    })
    expect(putRes.status).toBe(200)

    const discoverRes = await req('/api.linear.app', {
      headers: { Accept: 'application/json' },
    })
    expect(discoverRes.status).toBe(401)
    const body = (await discoverRes.json()) as any
    expect(body.preview.icon.url).toBe('https://icons.duckduckgo.com/ip3/linear.app.ico')
    expect(body.preview.icon.fallback).toBe('LI')
  })

  it('deletes a service', async () => {
    await seedService()
    const res = await mgmtReq('/services/api.github.com', { method: 'DELETE' })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/services')
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })

  it('returns 404 when deleting non-existent service', async () => {
    const res = await mgmtReq('/services/nonexistent', { method: 'DELETE' })
    expect(res.status).toBe(404)
  })

  it('lists services scoped by proxy token grants', async () => {
    await seedService('api.github.com')
    await mgmtReq('/services/api.linear.app', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: 'https://api.linear.app' }),
    })

    // Proxy token only has access to github
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', vault: TEST_ORG_ID },
    ])
    const res = await req('/services', {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].service).toBe('api.github.com')
  })

  it('lists all services for wildcard proxy token', async () => {
    await seedService('api.github.com')
    await mgmtReq('/services/api.linear.app', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: 'https://api.linear.app' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: '*' }])
    const res = await req('/services', {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(2)
  })
})

// ─── Credential Management (org-scoped) ────────────────────────────────────

describe('Credential Management', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('stores a credential', async () => {
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })
    expect(res.status).toBe(200)
  })

  it('stores credential with expiresAt', async () => {
    const expiresAt = new Date(Date.now() + 86400000).toISOString()
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: 'ghp_test123',
        expiresAt,
      }),
    })
    expect(res.status).toBe(200)
  })

  it('rejects credential without token or headers', async () => {
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  it('stores credential with explicit headers map', async () => {
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        headers: { 'Authorization': 'Bearer ghp_multi', 'X-Org-Id': 'org_123' },
      }),
    })
    expect(res.status).toBe(200)

    const cred = await getCredential(db, TEST_ORG_ID, 'api.github.com')
    expect(cred).not.toBeNull()
    const stored = await decryptCredentials(TEST_ENCRYPTION_KEY, cred?.encryptedCredentials)
    expect(stored.headers).toEqual({
      'Authorization': 'Bearer ghp_multi',
      'X-Org-Id': 'org_123',
    })
  })

  it('lists credentials for an org', async () => {
    await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].service).toBe('api.github.com')
    expect(body[0].hasCredentials).toBe(true)
  })

  it('rejects credential for non-existent service', async () => {
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/nonexistent`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'test' }),
    })
    expect(res.status).toBe(404)
  })

  it('deletes a credential', async () => {
    await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.github.com`, {
      method: 'DELETE',
    })
    expect(res.status).toBe(200)

    const list = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials`)
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })

  it('returns 404 when deleting non-existent credential', async () => {
    const res = await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/nonexistent`, {
      method: 'DELETE',
    })
    expect(res.status).toBe(404)
  })
})

// ─── Token Minting ──────────────────────────────────────────────────────────

describe('Token Minting', () => {
  it('mints a proxy token with grants format', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grants: [{ services: 'api.github.com', vault: TEST_ORG_ID }],
      }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
    expect(body.publicKey).toBeTruthy()
  })

  it('mints a proxy token with bindings format', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bindings: { 'api.github.com': { vault: TEST_ORG_ID } },
      }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
  })

  it('mints a management token', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rights: ['manage_services'],
        vaultAdmin: [TEST_ORG_ID],
      }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
  })

  it('rejects empty body', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  it('rejects grants with vault the caller cannot admin', async () => {
    const token = mintManagementToken(BISCUIT_PRIVATE_KEY, ['manage_vaults'], ['personal'])
    const res = await req('/tokens/mint', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        grants: [{ services: 'api.github.com', vault: 'restricted' }],
      }),
    })
    expect(res.status).toBe(403)
  })

  it('rejects bindings with vault the caller cannot admin', async () => {
    const token = mintManagementToken(BISCUIT_PRIVATE_KEY, ['manage_vaults'], ['personal'])
    const res = await req('/tokens/mint', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        bindings: { 'api.github.com': { vault: 'restricted' } },
      }),
    })
    expect(res.status).toBe(403)
  })

  it('rejects management token minting without manage_vaults', async () => {
    const token = mintManagementToken(BISCUIT_PRIVATE_KEY, ['manage_services'], [])
    const res = await req('/tokens/mint', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        rights: ['manage_services'],
        vaultAdmin: [TEST_ORG_ID],
      }),
    })
    expect(res.status).toBe(403)
  })

  it('mints grants without vault (no vault_admin check needed)', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grants: [{ services: 'api.github.com', methods: 'GET' }],
      }),
    })
    expect(res.status).toBe(200)
  })
})

// ─── Token Revocation ───────────────────────────────────────────────────────

describe('Token Revocation', () => {
  it('revokes a token', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com' },
    ])

    const res = await mgmtReq('/tokens/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, reason: 'compromised' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.ok).toBe(true)
    expect(body.revokedIds.length).toBeGreaterThan(0)
  })

  it('rejects revocation without token field', async () => {
    const res = await mgmtReq('/tokens/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  it('rejects revocation with invalid token', async () => {
    const res = await mgmtReq('/tokens/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'invalid_token' }),
    })
    expect(res.status).toBe(400)
  })
})

// ─── Token Restriction ──────────────────────────────────────────────────────

describe('Token Restriction', () => {
  it('restricts a token publicly', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', methods: ['GET', 'POST'], paths: '/' },
    ])

    const res = await req('/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, constraints: [{ methods: 'GET' }] }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
    expect(body.token).not.toBe(token)
  })

  it('rejects restriction without token', async () => {
    const res = await req('/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ constraints: [{ methods: 'GET' }] }),
    })
    expect(res.status).toBe(400)
  })

  it('rejects restriction without constraints', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: '*' }])
    const res = await req('/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, constraints: [] }),
    })
    expect(res.status).toBe(400)
  })

  it('rejects restriction with invalid token', async () => {
    const res = await req('/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'invalid', constraints: [{ methods: 'GET' }] }),
    })
    expect(res.status).toBe(400)
  })
})

// ─── Discovery (content-negotiated) ──────────────────────────────────────────

describe('Discovery', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('returns 401 JSON for unauthenticated agent with flow', async () => {
    const res = await req('/api.github.com', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toBe('Bearer realm="warden"')

    const body = (await res.json()) as any
    expect(body.service).toBe('GitHub')
    expect(body.canonical).toBe('api.github.com')
    expect(body.auth_url).toContain('http://localhost:3000/auth/api.github.com?flow_id=')
    expect(body.poll_url).toContain('http://localhost:3000/auth/status/')
    expect(body.proxy).toBe('http://localhost:3000/api.github.com')
    expect(body.auth_methods).toEqual([
      { type: 'oauth', mode: 'byo' },
      { type: 'api_key' },
    ])

    // Verify the flow was actually created and is pollable
    const flowId = body.poll_url.split('/auth/status/')[1]
    const pollRes = await req(`/auth/status/${flowId}`)
    expect(pollRes.status).toBe(202)
    const pollBody = (await pollRes.json()) as any
    expect(pollBody.status).toBe('pending')
  })

  it('returns HTML for unauthenticated browser', async () => {
    const res = await req('/api.github.com', {
      headers: { Accept: 'text/html' },
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('GitHub')
    expect(text).toContain('Enter API Key')
  })

  it('auto-registers unknown service on first discovery', async () => {
    // No seedService() — hit a completely unknown service
    const res = await req('/api.unknown.com', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(401)

    const body = (await res.json()) as any
    expect(body.canonical).toBe('api.unknown.com')
    expect(body.auth_url).toContain('/auth/api.unknown.com?flow_id=')
    expect(body.proxy).toBe('http://localhost:3000/api.unknown.com')
    expect(body.preview.icon.url).toBe('https://icons.duckduckgo.com/ip3/unknown.com.ico')
    expect(body.preview.icon.fallback).toBe('UN')
  })

  it('returns 200 JSON for authenticated agent', async () => {
    const token = mintProxyToken('api.github.com', TEST_ORG_ID)

    const res = await req('/api.github.com', {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.canonical).toBe('api.github.com')
  })

  it('returns 200 HTML for authenticated browser', async () => {
    const token = mintProxyToken('api.github.com', TEST_ORG_ID)

    const res = await req('/api.github.com', {
      headers: {
        Accept: 'text/html',
        Authorization: `Bearer ${token}`,
      },
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('GitHub')
  })

  it('returns authenticated status in discovery', async () => {
    const token = mintProxyToken('api.github.com', TEST_ORG_ID)
    const res = await req('/api.github.com', {
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
      },
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.authenticated).toBe(true)
  })

  it('auto-registers unknown service and returns 401', async () => {
    const res = await req('/unknown.api.com', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(401)
    const body = (await res.json()) as any
    expect(body.canonical).toBe('unknown.api.com')
    expect(body.auth_url).toContain('/auth/unknown.api.com?flow_id=')
  })

  it('returns 404 for reserved paths in discovery', async () => {
    const res = await req('/auth', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(404)
  })
})

// ─── Documentation Routes (content-negotiated) ──────────────────────────────

describe('Documentation Routes', () => {
  beforeEach(async () => {
    await seedService()
    await upsertDocPage(
      db,
      'api.github.com',
      'sitemap/index.json',
      JSON.stringify({
        level: 0,
        service: 'GitHub',
        hostname: 'api.github.com',
        api_type: 'rest',
        base_url: '/api.github.com',
        description: 'REST API for GitHub',
        auth: [{ type: 'oauth', setup_url: '/auth/api.github.com/oauth' }],
      }),
      'enriched',
    )
    await upsertDocPage(
      db,
      'api.github.com',
      'sitemap/resources.json',
      JSON.stringify({
        level: 1,
        resources: [
          {
            name: 'Repositories',
            slug: 'repositories',
            description: 'Repository operations',
            common_operations: [{ method: 'GET', path: '/repos', summary: 'List repos' }],
          },
        ],
      }),
      'enriched',
    )
  })

  it('returns JSON docs for agents', async () => {
    const res = await req('/api.github.com/sitemap/', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/json')
    const body = (await res.json()) as any
    expect(body.level).toBe(0)
    expect(body.hostname).toBe('api.github.com')
  })

  it('returns HTML docs for humans', async () => {
    const res = await req('/api.github.com/sitemap/', {
      headers: { Accept: 'text/html' },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    const text = await res.text()
    expect(text).toContain('Documentation')
    expect(text).toContain('sitemap/index.json')
    expect(text).toContain('Raw JSON')
  })

  it('renders nested docs page as HTML when requested by browser', async () => {
    const res = await req('/api.github.com/sitemap/resources.json', {
      headers: { Accept: 'text/html' },
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('sitemap/resources.json')
    expect(text).toContain('Repositories')
  })
})

// ─── Proxy ───────────────────────────────────────────────────────────────────

describe('Proxy', () => {
  it('rejects requests without auth', async () => {
    await seedService()
    const res = await req('/api.github.com/user')
    expect(res.status).toBe(401)
  })

  it('rejects requests with invalid token', async () => {
    await seedService()
    const res = await req('/api.github.com/user', {
      headers: { Authorization: 'Bearer invalid_token' },
    })
    expect(res.status).toBe(401)
  })

  it('returns 404 for unknown service in proxy', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: 'unknown.api.com' }])
    const res = await req('/unknown.api.com/path', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
  })

  it('returns 403 for forbidden method', async () => {
    await seedService()
    // Token allows only GET
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', methods: 'GET' },
    ])
    const res = await req('/api.github.com/repos', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })

  it('returns 403 for revoked proxy token', async () => {
    await seedService()
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: 'api.github.com' }])
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(token, publicKey)
    await revokeToken(db, revIds[0], 'test')

    const res = await req('/api.github.com/user', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(403)
  })

  it('returns 404 when no credential found for org', async () => {
    await seedService()
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', vault: TEST_ORG_ID },
    ])
    const res = await req('/api.github.com/user', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
    const body = (await res.json()) as any
    expect(body.error).toContain('No credential')
  })

  it('proxies request with bearer auth and returns upstream response', async () => {
    await seedServiceWithCred()
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', vault: TEST_ORG_ID },
    ])

    // Mock fetch for upstream
    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ login: 'alice' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    try {
      const res = await req('/api.github.com/user', {
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

  it('proxies with apiKey auth scheme', async () => {
    // Register service with apiKey auth scheme
    await mgmtReq('/services/api.example.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.example.com',
        authSchemes: [{ type: 'apiKey', in: 'header', name: 'X-API-Key' }],
      }),
    })
    await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.example.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'sk_test_key' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.example.com', vault: TEST_ORG_ID },
    ])

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('ok', { status: 200 }),
    )

    try {
      const res = await req('/api.example.com/data', {
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
    await mgmtReq('/services/api.basic.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.basic.com',
        authSchemes: [{ type: 'http', scheme: 'basic' }],
      }),
    })
    await mgmtReq(`/vaults/${TEST_ORG_ID}/credentials/api.basic.com`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'user:pass' }),
    })

    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.basic.com', vault: TEST_ORG_ID },
    ])

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('ok', { status: 200 }),
    )

    try {
      const res = await req('/api.basic.com/data', {
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
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', vault: TEST_ORG_ID },
    ])

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response('created', { status: 201 }),
    )

    try {
      const res = await req('/api.github.com/repos', {
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

  it('returns 404 for reserved paths in proxy', async () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: 'tokens' }])
    const res = await req('/tokens/something', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(res.status).toBe(404)
  })
})

// ─── Legacy Redirect ────────────────────────────────────────────────────────

describe('Legacy Redirect', () => {
  it('redirects /proxy/:service/* to /:service/*', async () => {
    const res = await req('/proxy/api.github.com/user', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.github.com/user')
  })
})

describe('Protocol prefix redirect', () => {
  it('redirects /https://hostname/path to /hostname/path', async () => {
    const res = await req('/https://api.linear.app/graphql', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.linear.app/graphql')
  })

  it('redirects /http://hostname/path to /hostname/path', async () => {
    const res = await req('/http://api.linear.app/graphql', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.linear.app/graphql')
  })

  it('preserves query string on redirect', async () => {
    const res = await req('/https://api.linear.app/graphql?foo=bar', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.linear.app/graphql?foo=bar')
  })

  it('redirects bare hostname without trailing path', async () => {
    const res = await req('/https://api.linear.app', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.linear.app')
  })
})

// ─── Auth Flow Polling ──────────────────────────────────────────────────────

describe('Auth Flow Polling', () => {
  it('returns 404 for unknown flow', async () => {
    const res = await req('/auth/status/nonexistent')
    expect(res.status).toBe(404)
  })

  it('returns pending status for active flow', async () => {
    await createAuthFlow(redis, {
      id: 'test-flow-1',
      service: 'api.github.com',
      method: 'api_key',
      expiresAt: new Date(Date.now() + 600000),
    })

    const res = await req('/auth/status/test-flow-1')
    expect(res.status).toBe(202)
    const body = (await res.json()) as any
    expect(body.status).toBe('pending')
  })

  it('returns completed status with token', async () => {
    await createAuthFlow(redis, {
      id: 'test-flow-2',
      service: 'api.github.com',
      method: 'api_key',
      expiresAt: new Date(Date.now() + 600000),
    })
    await completeAuthFlow(redis, 'test-flow-2', {
      wardenToken: 'wdn_test',
      identity: 'alice',
      orgId: TEST_ORG_ID,
    })

    const res = await req('/auth/status/test-flow-2')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.status).toBe('completed')
    expect(body.token).toBe('wdn_test')
    expect(body.identity).toBe('alice')
  })

  it('returns 404 for expired flow', async () => {
    await createAuthFlow(redis, {
      id: 'test-flow-expired',
      service: 'api.github.com',
      method: 'api_key',
      expiresAt: new Date(Date.now() - 1000), // already expired
    })

    const res = await req('/auth/status/test-flow-expired')
    expect(res.status).toBe(404)
  })
})

// ─── API Key Flow ───────────────────────────────────────────────────────────

describe('API Key Flow', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('shows API key form', async () => {
    const res = await sessionReq('/auth/api.github.com/api-key')
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('api_key')
  })

  it('returns 404 for unknown service on form', async () => {
    const res = await sessionReq('/auth/unknown.api/api-key')
    expect(res.status).toBe(404)
  })

  it('submits API key and stores credential', async () => {
    // First get the form to create a flow
    const formRes = await sessionReq('/auth/api.github.com/api-key?flow_id=ak-flow-1')
    expect(formRes.status).toBe(200)

    // Submit the API key
    const res = await sessionReq('/auth/api.github.com/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=ghp_testkey&flow_id=ak-flow-1',
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('wdn_') // Should show the minted token
  })

  it('rejects empty API key', async () => {
    const res = await sessionReq('/auth/api.github.com/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=&flow_id=ak-flow-2',
    })
    expect(res.status).toBe(400)
  })

  it('returns 404 for unknown service on submit', async () => {
    const res = await sessionReq('/auth/unknown.api/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=test123',
    })
    expect(res.status).toBe(404)
  })

  it('uses existing flow and does not re-create it', async () => {
    // Create a flow via form visit
    await sessionReq('/auth/api.github.com/api-key?flow_id=ak-existing')
    // Visit again with same flow_id
    const res = await sessionReq('/auth/api.github.com/api-key?flow_id=ak-existing')
    expect(res.status).toBe(200)
  })

  it('submits API key without flow_id', async () => {
    const res = await sessionReq('/auth/api.github.com/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'api_key=ghp_noflow',
    })
    expect(res.status).toBe(200)
  })

  it('validates API key via identity_url (bearer auth)', async () => {
    // Register service with identity_url in authConfig
    await mgmtReq('/services/validated.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://validated.api',
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
      const res = await sessionReq('/auth/validated.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test_key_123',
      })
      expect(res.status).toBe(200)
      const text = await res.text()
      expect(text).toContain('wdn_')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('rejects API key when identity_url returns error', async () => {
    await mgmtReq('/services/rejected.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://rejected.api',
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
      const res = await sessionReq('/auth/rejected.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=bad_key',
      })
      expect(res.status).toBe(400)
      const text = await res.text()
      expect(text).toContain('rejected')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with api_key auth method', async () => {
    await mgmtReq('/services/apikey-svc.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://apikey-svc.api',
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
      const res = await sessionReq('/auth/apikey-svc.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=sk_test',
      })
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with basic auth method', async () => {
    await mgmtReq('/services/basic-svc.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://basic-svc.api',
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
      const res = await sessionReq('/auth/basic-svc.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=user:pass',
      })
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('validates API key with POST identity method', async () => {
    await mgmtReq('/services/post-id.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://post-id.api',
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
      const res = await sessionReq('/auth/post-id.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test123',
      })
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles identity validation failure gracefully', async () => {
    await mgmtReq('/services/fail-id.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://fail-id.api',
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
      const res = await sessionReq('/auth/fail-id.api/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'api_key=test123',
      })
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  // ─── Programmatic (JSON) API Key Submission ──────────────────────────────

  it('accepts JSON POST with api_key and flow_id in query', async () => {
    // Create a flow first
    await sessionReq('/auth/api.github.com/api-key?flow_id=json-flow-1')

    const res = await sessionReq('/auth/api.github.com/api-key?flow_id=json-flow-1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'ghp_jsonkey' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
    expect(body.identity).toBe('default')
  })

  it('accepts JSON POST with flow_id in body', async () => {
    await sessionReq('/auth/api.github.com/api-key?flow_id=json-flow-2')

    const res = await sessionReq('/auth/api.github.com/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'ghp_jsonkey2', flow_id: 'json-flow-2' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.token).toMatch(/^wdn_/)
  })

  it('completes flow so polling returns token (JSON path)', async () => {
    await sessionReq('/auth/api.github.com/api-key?flow_id=json-poll-1')

    await sessionReq('/auth/api.github.com/api-key?flow_id=json-poll-1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'ghp_pollkey' }),
    })

    const poll = await req('/auth/status/json-poll-1')
    expect(poll.status).toBe(200)
    const body = (await poll.json()) as any
    expect(body.status).toBe('completed')
    expect(body.token).toMatch(/^wdn_/)
  })

  it('rejects JSON POST with missing api_key', async () => {
    const res = await sessionReq('/auth/api.github.com/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
    const body = (await res.json()) as any
    expect(body.error).toContain('api_key')
  })

  it('returns JSON 404 for unknown service', async () => {
    const res = await sessionReq('/auth/unknown.api/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'test' }),
    })
    expect(res.status).toBe(404)
    const body = (await res.json()) as any
    expect(body.error).toContain('unknown.api')
  })

  it('rejects JSON POST when identity_url returns error', async () => {
    await mgmtReq('/services/json-rejected.api', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://json-rejected.api',
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
      const res = await sessionReq('/auth/json-rejected.api/api-key', {
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

// ─── OAuth Flow ─────────────────────────────────────────────────────────────

describe('OAuth Flow', () => {
  beforeEach(async () => {
    // Register a service with OAuth configured
    await mgmtReq('/services/github-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.github.com',
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
    const res = await sessionReq('/auth/github-oauth.com/oauth', {
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
    const res = await sessionReq('/auth/unknown.api/oauth', { redirect: 'manual' })
    expect(res.status).toBe(404)
  })

  it('returns 400 for service without OAuth config', async () => {
    await seedService() // GitHub without OAuth config
    const res = await sessionReq('/auth/api.github.com/oauth', { redirect: 'manual' })
    expect(res.status).toBe(400)
  })

  it('handles OAuth callback error param', async () => {
    const res = await req('/auth/github-oauth.com/oauth/callback?error=access_denied')
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('access_denied')
  })

  it('rejects callback without code or state', async () => {
    const res = await req('/auth/github-oauth.com/oauth/callback')
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('Missing code or state')
  })

  it('rejects callback with unknown flow state', async () => {
    const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=unknown')
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('Unknown or expired')
  })

  it('rejects callback for expired flow', async () => {
    await createAuthFlow(redis, {
      id: 'expired-flow',
      service: 'github-oauth.com',
      method: 'oauth',
      codeVerifier: 'test',
      expiresAt: new Date(Date.now() - 1000),
    })

    const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=expired-flow')
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('expired')
  })

  it('rejects callback for already completed flow', async () => {
    await createAuthFlow(redis, {
      id: 'completed-flow',
      service: 'github-oauth.com',
      method: 'oauth',
      codeVerifier: 'test',
      expiresAt: new Date(Date.now() + 600000),
    })
    await completeAuthFlow(redis, 'completed-flow', {
      wardenToken: 'wdn_old',
      identity: 'alice',
      orgId: TEST_ORG_ID,
    })

    const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=completed-flow')
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('already completed')
  })

  it('handles failed token exchange', async () => {
    await createAuthFlow(redis, {
      id: 'token-fail-flow',
      service: 'github-oauth.com',
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
      const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=token-fail-flow')
      expect(res.status).toBe(500)
      const text = await res.text()
      expect(text).toContain('Token exchange failed')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles missing access token in response', async () => {
    await createAuthFlow(redis, {
      id: 'no-token-flow',
      service: 'github-oauth.com',
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
      const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=no-token-flow')
      expect(res.status).toBe(500)
      const text = await res.text()
      expect(text).toContain('No access token')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('completes successful OAuth flow', async () => {
    await createAuthFlow(redis, {
      id: 'success-flow',
      service: 'github-oauth.com',
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
      const res = await req('/auth/github-oauth.com/oauth/callback?code=abc&state=success-flow')
      expect(res.status).toBe(200)
      const text = await res.text()
      expect(text).toContain('wdn_')

      // Verify flow was completed
      const flow = await getAuthFlow(redis, 'success-flow')
      expect(flow?.status).toBe('completed')
      expect(flow?.wardenToken).toMatch(/^wdn_/)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('resolves identity via whoami after token exchange', async () => {
    // Register service with identity_url in authConfig
    await mgmtReq('/services/id-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.id-oauth.com',
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
    await createAuthFlow(redis, {
      id: 'id-flow',
      service: 'id-oauth.com',
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
      const res = await req('/auth/id-oauth.com/oauth/callback?code=abc&state=id-flow')
      expect(res.status).toBe(200)

      const flow = await getAuthFlow(redis, 'id-flow')
      expect(flow?.identity).toBe('carol@example.com')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('resolves identity via POST method', async () => {
    await mgmtReq('/services/post-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.post-oauth.com',
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
    await createAuthFlow(redis, {
      id: 'post-id-flow',
      service: 'post-oauth.com',
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
      const res = await req('/auth/post-oauth.com/oauth/callback?code=abc&state=post-id-flow')
      expect(res.status).toBe(200)
      const flow = await getAuthFlow(redis, 'post-id-flow')
      expect(flow?.identity).toBe('frank')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('falls back to default identity when whoami fails', async () => {
    await mgmtReq('/services/fail-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.fail-oauth.com',
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
    await createAuthFlow(redis, {
      id: 'fail-id-flow',
      service: 'fail-oauth.com',
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
      const res = await req('/auth/fail-oauth.com/oauth/callback?code=abc&state=fail-id-flow')
      expect(res.status).toBe(200)
      const flow = await getAuthFlow(redis, 'fail-id-flow')
      expect(flow?.identity).toBe('default')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('falls back to default identity when identity_url set but no identity_path', async () => {
    await mgmtReq('/services/nopath-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.nopath-oauth.com',
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
    await createAuthFlow(redis, {
      id: 'nopath-flow',
      service: 'nopath-oauth.com',
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
      const res = await req('/auth/nopath-oauth.com/oauth/callback?code=abc&state=nopath-flow')
      expect(res.status).toBe(200)
      const flow = await getAuthFlow(redis, 'nopath-flow')
      expect(flow?.identity).toBe('default')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('handles token exchange with custom token_path and token_accept', async () => {
    await mgmtReq('/services/custom-oauth.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://api.custom-oauth.com',
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
    await createAuthFlow(redis, {
      id: 'custom-token-flow',
      service: 'custom-oauth.com',
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
      const res = await req('/auth/custom-oauth.com/oauth/callback?code=abc&state=custom-token-flow')
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('uses session orgId when flow has no orgId', async () => {
    await createAuthFlow(redis, {
      id: 'no-org-flow',
      service: 'github-oauth.com',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      expiresAt: new Date(Date.now() + 600000),
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ access_token: 'token' }), { status: 200 }),
    )

    try {
      const res = await sessionReq('/auth/github-oauth.com/oauth/callback?code=abc&state=no-org-flow')
      expect(res.status).toBe(200)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('rejects callback for service with missing OAuth token config', async () => {
    // Register service without oauth2 scheme (no tokenUrl)
    await mgmtReq('/services/no-token-url.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        baseUrl: 'https://no-token-url.com',
        oauthClientId: 'cid',
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        // Note: no oauth2 scheme
      }),
    })
    await createAuthFlow(redis, {
      id: 'no-token-url-flow',
      service: 'no-token-url.com',
      method: 'oauth',
      codeVerifier: 'test_verifier',
      orgId: TEST_ORG_ID,
      expiresAt: new Date(Date.now() + 600000),
    })

    const res = await req('/auth/no-token-url.com/oauth/callback?code=abc&state=no-token-url-flow')
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(text).toContain('OAuth not configured')
  })
})

// ─── Key Generation ─────────────────────────────────────────────────────────

describe('Key Generation', () => {
  it('generates an Ed25519 keypair', async () => {
    const res = await mgmtReq('/keys/generate', { method: 'POST' })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.privateKey).toBeTruthy()
    expect(body.publicKey).toBeTruthy()
  })
})

// ─── Biscuit Functions ──────────────────────────────────────────────────────

describe('Biscuit Functions', () => {
  const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)

  it('strips wdn_ prefix', () => {
    expect(stripPrefix('wdn_abc')).toBe('abc')
  })

  it('strips vt_ legacy prefix', () => {
    expect(stripPrefix('vt_abc')).toBe('abc')
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

  it('mints token with TTL', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', ttl: '1h' },
    ])
    expect(token).toMatch(/^wdn_/)
  })

  it('mints token with metadata', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', metadata: { userId: 'alice' } },
    ])
    const identity = extractIdentityFromToken(token, publicKey, 'api.github.com')
    expect(identity).toBe('alice')
  })

  it('extractIdentityFromToken returns null for no match', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', metadata: { userId: 'alice' } },
    ])
    const identity = extractIdentityFromToken(token, publicKey, 'other.api.com')
    expect(identity).toBeNull()
  })

  it('extractIdentityFromToken returns null for invalid token', () => {
    const identity = extractIdentityFromToken('invalid', publicKey, 'test')
    expect(identity).toBeNull()
  })

  it('extractIdentityFromToken matches wildcard service', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: '*', metadata: { userId: 'bob' } },
    ])
    const identity = extractIdentityFromToken(token, publicKey, 'anything.api.com')
    expect(identity).toBe('bob')
  })

  it('extractGrants returns grant info', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', methods: ['GET', 'POST'], paths: '/user' },
    ])
    const grants = extractGrants(token, publicKey)
    expect(grants).toHaveLength(1)
    expect(grants[0].services).toEqual(['api.github.com'])
    expect(grants[0].methods).toEqual(['GET', 'POST'])
    expect(grants[0].paths).toEqual(['/user'])
  })

  it('extractGrants returns empty for invalid token', () => {
    const grants = extractGrants('invalid', publicKey)
    expect(grants).toEqual([])
  })

  it('extractVaultFromToken returns vault', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', vault: 'team-a' },
    ])
    const vault = extractVaultFromToken(token, publicKey, 'api.github.com')
    expect(vault).toBe('team-a')
  })

  it('extractVaultFromToken returns null when no vault', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com' },
    ])
    const vault = extractVaultFromToken(token, publicKey, 'api.github.com')
    expect(vault).toBeNull()
  })

  it('extractVaultFromToken returns null for invalid token', () => {
    const vault = extractVaultFromToken('invalid', publicKey, 'test')
    expect(vault).toBeNull()
  })

  it('extractManagementRights returns empty for invalid token', () => {
    const mgmt = extractManagementRights('invalid', publicKey)
    expect(mgmt.rights).toEqual([])
    expect(mgmt.vaultAdminSlugs).toEqual([])
  })

  it('authorizeRequest returns authorized for matching grant', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', methods: 'GET', paths: '/user' },
    ])
    const result = authorizeRequest(token, publicKey, 'api.github.com', 'GET', '/user')
    expect(result.authorized).toBe(true)
  })

  it('authorizeRequest returns forbidden for non-matching method', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: 'api.github.com', methods: 'GET' },
    ])
    const result = authorizeRequest(token, publicKey, 'api.github.com', 'POST', '/user')
    expect(result.authorized).toBe(false)
    expect(result.error).toBeTruthy()
  })

  it('restrictToken with multiple alternatives', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [
      { services: ['api.github.com', 'api.linear.app'] },
    ])
    const restricted = restrictToken(token, publicKey, [
      { services: 'api.github.com', methods: 'GET' },
      { services: 'api.linear.app', methods: 'POST' },
    ])
    expect(restricted).toMatch(/^wdn_/)
    expect(restricted).not.toBe(token)
  })

  it('restrictToken with TTL constraint', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: '*' }])
    const restricted = restrictToken(token, publicKey, [
      { methods: 'GET', ttl: '1h' },
    ])
    expect(restricted).toMatch(/^wdn_/)
  })

  it('restrictToken with path constraint', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, [{ services: '*' }])
    const restricted = restrictToken(token, publicKey, [
      { paths: ['/user', '/repos'] },
    ])
    expect(restricted).toMatch(/^wdn_/)
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

// ─── Discovery Functions ────────────────────────────────────────────────────

describe('Discovery Functions', () => {
  it('wantsJson returns false for undefined', () => {
    expect(wantsJson(undefined)).toBe(false)
  })

  it('wantsJson returns true for application/json', () => {
    expect(wantsJson('application/json')).toBe(true)
  })

  it('wantsJson returns false for text/html', () => {
    expect(wantsJson('text/html')).toBe(false)
  })

  it('wantsJson returns true for */* (curl default)', () => {
    expect(wantsJson('*/*')).toBe(true)
  })

  it('wantsJson returns false for browser Accept with */*', () => {
    expect(wantsJson('text/html,application/xhtml+xml,*/*;q=0.8')).toBe(false)
  })

  it('buildUnauthDiscovery includes description and docs_url', () => {
    const svc = {
      service: 'api.github.com',
      baseUrl: 'https://api.github.com',
      displayName: 'GitHub',
      description: 'GitHub REST API',
      authSchemes: null,
      oauthClientId: null,
      encryptedOauthClientSecret: null,
      apiType: null,
      docsUrl: 'https://docs.github.com',
      preview: null,
      authConfig: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    const result = buildUnauthDiscovery(svc, 'http://localhost:3000') as any
    expect(result.service).toBe('GitHub')
    expect(result.description).toBe('GitHub REST API')
    expect(result.docs_url).toBe('https://docs.github.com')
    expect(result.proxy).toBe('http://localhost:3000/api.github.com')
    expect(result.auth_url).toBe('http://localhost:3000/auth/api.github.com')
    expect(result.auth_methods).toEqual([{ type: 'api_key' }])
  })

  it('buildUnauthDiscovery includes preview when set', () => {
    const svc = {
      service: 'test.api',
      baseUrl: 'https://test.api',
      displayName: null,
      description: null,
      authSchemes: null,
      oauthClientId: null,
      encryptedOauthClientSecret: null,
      apiType: null,
      docsUrl: null,
      preview: JSON.stringify({ example: true }),
      authConfig: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    const result = buildUnauthDiscovery(svc, 'http://localhost:3000') as any
    expect(result.service).toBe('test.api')
    expect(result.preview).toEqual({ example: true })
  })

  it('buildAuthDiscovery includes api_type and proxy', () => {
    const svc = {
      service: 'api.github.com',
      baseUrl: 'https://api.github.com',
      displayName: 'GitHub',
      description: null,
      authSchemes: null,
      oauthClientId: null,
      encryptedOauthClientSecret: null,
      apiType: 'rest',
      docsUrl: 'https://docs.github.com',
      preview: null,
      authConfig: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    const result = buildAuthDiscovery(svc, 'http://localhost:3000') as any
    expect(result.authenticated).toBe(true)
    expect(result.api_type).toBe('rest')
    expect(result.proxy).toBe('http://localhost:3000/api.github.com')
    expect(result.docs_url).toBe('https://docs.github.com')
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
    await upsertService(db, 'test.api', { baseUrl: 'https://test.api' })
    const enc1 = await encryptCredentials(TEST_ENCRYPTION_KEY, { headers: { Authorization: 'Bearer token1' } })
    const enc2 = await encryptCredentials(TEST_ENCRYPTION_KEY, { headers: { Authorization: 'Bearer token2' } })
    await upsertCredential(db, TEST_ORG_ID, 'test.api', 'default', enc1)
    await upsertCredential(db, TEST_ORG_ID, 'test.api', 'default', enc2)
    const cred = await getCredential(db, TEST_ORG_ID, 'test.api')
    const stored = await decryptCredentials(TEST_ENCRYPTION_KEY, cred?.encryptedCredentials)
    expect(stored.headers.Authorization).toBe('Bearer token2')
  })

  it('listServicesWithCredentialCounts returns per-service popularity', async () => {
    await upsertService(db, 'api.one.test', { baseUrl: 'https://api.one.test' })
    await upsertService(db, 'api.two.test', { baseUrl: 'https://api.two.test' })

    const encrypted = await encryptCredentials(TEST_ENCRYPTION_KEY, {
      headers: { Authorization: 'Bearer shared-token' },
    })
    await upsertCredential(db, 'personal', 'api.one.test', 'alice', encrypted)
    await upsertCredential(db, 'team-alpha', 'api.one.test', 'bob', encrypted)

    const rows = await listServicesWithCredentialCounts(db)
    const serviceOne = rows.find(row => row.service === 'api.one.test')
    const serviceTwo = rows.find(row => row.service === 'api.two.test')

    expect(serviceOne?.credentialCount).toBe(2)
    expect(serviceTwo?.credentialCount).toBe(0)
  })

  it('countCredentialsForService returns zero and non-zero counts', async () => {
    expect(await countCredentialsForService(db, 'api.none.test')).toBe(0)

    await upsertService(db, 'api.counted.test', { baseUrl: 'https://api.counted.test' })
    const encrypted = await encryptCredentials(TEST_ENCRYPTION_KEY, {
      headers: { Authorization: 'Bearer counted' },
    })
    await upsertCredential(db, 'personal', 'api.counted.test', 'alice', encrypted)

    expect(await countCredentialsForService(db, 'api.counted.test')).toBe(1)
  })

  it('upsertOAuthApp stores and updates a BYO oauth app', async () => {
    const secret1 = Buffer.from('secret-1')
    const secret2 = Buffer.from('secret-2')

    await upsertOAuthApp(db, 'personal', 'api.github.com', {
      clientId: 'client-1',
      encryptedClientSecret: secret1,
      scopes: 'repo',
    })

    await upsertOAuthApp(db, 'personal', 'api.github.com', {
      clientId: 'client-2',
      encryptedClientSecret: secret2,
      scopes: 'repo user',
    })

    const app = await getOAuthApp(db, 'personal', 'api.github.com')
    expect(app).not.toBeNull()
    expect(app!.clientId).toBe('client-2')
    expect(Buffer.from(app!.encryptedClientSecret ?? []).toString()).toBe('secret-2')
    expect(app!.scopes).toBe('repo user')
  })

  it('upsertOAuthApp keeps existing secret and scopes when omitted', async () => {
    const secret = Buffer.from('persisted-secret')

    await upsertOAuthApp(db, 'personal', 'api.linear.app', {
      clientId: 'client-a',
      encryptedClientSecret: secret,
      scopes: 'read write',
    })

    await upsertOAuthApp(db, 'personal', 'api.linear.app', {
      clientId: 'client-b',
    })

    const app = await getOAuthApp(db, 'personal', 'api.linear.app')
    expect(app).not.toBeNull()
    expect(app!.clientId).toBe('client-b')
    expect(Buffer.from(app!.encryptedClientSecret ?? []).toString()).toBe('persisted-secret')
    expect(app!.scopes).toBe('read write')
  })

  it('createAuthFlow with oauthSource stores source on Redis flow', async () => {
    await createAuthFlow(redis, {
      id: 'oauth-flow',
      service: 'api.github.com',
      method: 'oauth',
      codeVerifier: 'pkce-verifier',
      orgId: TEST_ORG_ID,
      oauthSource: 'byo',
      expiresAt: new Date(Date.now() + 60_000),
    })

    const flow = await getAuthFlow(redis, 'oauth-flow')
    expect(flow).not.toBeNull()
    expect(flow!.method).toBe('oauth')
    expect(flow!.oauthSource).toBe('byo')
    expect(flow!.codeVerifier).toBe('pkce-verifier')
    expect(flow!.orgId).toBe(TEST_ORG_ID)
  })
})

// ─── Doc Page Queries ───────────────────────────────────────────────────────

describe('Doc Page Queries', () => {
  it('getDocPage returns null when not found', async () => {
    const page = await getDocPage(db, 'unknown.api', 'index.json')
    expect(page).toBeNull()
  })

  it('upsertDocPage creates and retrieves a page', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{"level":0}', 'skeleton')
    const page = await getDocPage(db, 'api.github.com', 'sitemap/index.json')
    expect(page).not.toBeNull()
    expect(page?.content).toBe('{"level":0}')
    expect(page?.status).toBe('skeleton')
  })

  it('upsertDocPage updates existing page', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{"v":1}', 'skeleton')
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{"v":2}', 'enriched')
    const page = await getDocPage(db, 'api.github.com', 'sitemap/index.json')
    expect(page?.content).toBe('{"v":2}')
    expect(page?.status).toBe('enriched')
  })

  it('listDocPages returns all pages for a hostname', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'skeleton')
    await upsertDocPage(db, 'api.github.com', 'sitemap/repos.json', '{}', 'enriched')
    await upsertDocPage(db, 'other.api', 'sitemap/index.json', '{}', 'skeleton')
    const pages = await listDocPages(db, 'api.github.com')
    expect(pages).toHaveLength(2)
  })

  it('listSkeletonPages returns only skeleton pages', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'skeleton')
    await upsertDocPage(db, 'api.github.com', 'sitemap/repos.json', '{}', 'enriched')
    const pages = await listSkeletonPages(db, 'api.github.com')
    expect(pages).toHaveLength(1)
    expect(pages[0].path).toBe('sitemap/index.json')
  })

  it('deleteDocPages removes all pages for a hostname', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'skeleton')
    await upsertDocPage(db, 'api.github.com', 'sitemap/repos.json', '{}', 'enriched')
    await deleteDocPages(db, 'api.github.com')
    const pages = await listDocPages(db, 'api.github.com')
    expect(pages).toHaveLength(0)
  })

  it('upsertDocPage with custom ttlDays', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'skeleton', 30)
    const page = await getDocPage(db, 'api.github.com', 'sitemap/index.json')
    expect(page?.ttlDays).toBe(30)
  })

  it('listStaleDocPages returns pages past their TTL', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'enriched', 1)
    // Make the page stale by backdating generated_at
    await db.execute(
      sql`UPDATE warden.doc_pages SET generated_at = now() - interval '30 days' WHERE hostname = 'api.github.com'`,
    )
    const stale = await listStaleDocPages(db, 'api.github.com')
    expect(stale).toHaveLength(1)
    expect(stale[0].path).toBe('sitemap/index.json')
  })

  it('listStaleDocPages excludes fresh pages', async () => {
    await upsertDocPage(db, 'api.github.com', 'sitemap/index.json', '{}', 'enriched', 7)
    const stale = await listStaleDocPages(db, 'api.github.com')
    expect(stale).toHaveLength(0)
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

// ─── Deterministic Discovery ────────────────────────────────────────────────

describe('Deterministic Discovery', () => {
  it('groups versioned paths by resource, not version prefix', async () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Test API', version: '1.0' },
      paths: {
        '/v1/customers': { get: { summary: 'List customers' } },
        '/v1/customers/{id}': { get: { summary: 'Get customer' } },
        '/v1/invoices': { get: { summary: 'List invoices' } },
        '/v1/invoices/{id}': { get: { summary: 'Get invoice' } },
      },
    }

    const service = {
      service: 'api.test.com',
      baseUrl: 'https://api.test.com',
      displayName: 'Test',
      description: null,
      authSchemes: '[]',
      oauthClientId: null,
      encryptedOauthClientSecret: null,
      apiType: 'rest',
      docsUrl: null,
      preview: null,
      authConfig: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    const probe: ProbeResult = {
      apiType: 'rest',
      specContent: JSON.stringify(spec),
      specUrl: null,
      graphqlSchema: null,
      docsUrl: null,
      oauthMeta: null,
      externalDocsUrls: [],
    }

    const result = await runDeterministicDiscovery(
      { db, hostname: 'api.test.com', service, baseUrl: 'http://localhost' },
      probe,
    )

    // Should find 2 resources (customers, invoices), not 1 (v1)
    expect(result.resourcesFound.length).toBe(2)
    expect(result.resourcesFound).toContain('customers')
    expect(result.resourcesFound).toContain('invoices')

    // Should have resource detail pages for each
    const customersPage = await getDocPage(db, 'api.test.com', 'sitemap/customers.json')
    const invoicesPage = await getDocPage(db, 'api.test.com', 'sitemap/invoices.json')
    expect(customersPage).toBeTruthy()
    expect(invoicesPage).toBeTruthy()
  })

  it('updates service record with apiType and description from spec', async () => {
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Acme API', version: '1.0', description: 'The Acme platform API' },
      paths: {
        '/widgets': { get: { summary: 'List widgets' } },
      },
    }

    // Pre-register with no apiType or description
    await upsertService(db, 'api.acme.com', { baseUrl: 'https://api.acme.com' })

    const service = (await getService(db, 'api.acme.com'))!
    expect(service.apiType).toBeNull()
    expect(service.description).toBeNull()

    await runDeterministicDiscovery(
      { db, hostname: 'api.acme.com', service, baseUrl: 'http://localhost' },
      {
        apiType: 'rest',
        specContent: JSON.stringify(spec),
        specUrl: null,
        graphqlSchema: null,
        docsUrl: 'https://docs.acme.com',
        oauthMeta: null,
        externalDocsUrls: [],
      },
    )

    const updated = await getService(db, 'api.acme.com')
    expect(updated?.apiType).toBe('rest')
    expect(updated?.description).toBe('The Acme platform API')
    expect(updated?.docsUrl).toBe('https://docs.acme.com')
  })
})
