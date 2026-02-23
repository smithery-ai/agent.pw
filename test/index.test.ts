import { env, SELF } from 'cloudflare:test'
import { describe, it, expect, beforeEach } from 'vitest'

const ADMIN_KEY = 'sk_test_admin_key_12345'

function adminHeaders() {
  return { Authorization: `Bearer ${ADMIN_KEY}`, 'Content-Type': 'application/json' }
}

async function adminFetch(path: string, init?: RequestInit) {
  return SELF.fetch(`https://auth-proxy.test${path}`, {
    ...init,
    headers: { ...adminHeaders(), ...init?.headers },
  })
}

async function fetchWithToken(path: string, token: string, init?: RequestInit) {
  return SELF.fetch(`https://auth-proxy.test${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  })
}

/** Helper to register a service */
async function setupService(name: string, baseUrl: string, description?: string) {
  await adminFetch(`/admin/services/${name}`, {
    method: 'PUT',
    body: JSON.stringify({ baseUrl, authMethod: 'bearer', description }),
  })
}

/** Helper to store a credential */
async function setupCredential(service: string, identity: string, token: string, metadata?: Record<string, string>) {
  await adminFetch(`/admin/credentials/${service}`, {
    method: 'PUT',
    body: JSON.stringify({ identity, token, metadata }),
  })
}

describe('Auth Proxy', () => {
  // ─── Health ──────────────────────────────────────────────────────────────

  it('GET / returns health check', async () => {
    const res = await SELF.fetch('https://auth-proxy.test/')
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.status).toBe('ok')
    expect(body.service).toBe('auth-proxy')
  })

  // ─── Admin Auth ────────────────────────────────────────────────────────

  it('rejects requests without auth', async () => {
    const res = await SELF.fetch('https://auth-proxy.test/admin/services')
    expect(res.status).toBe(401)
  })

  it('rejects requests with wrong admin key', async () => {
    const res = await SELF.fetch('https://auth-proxy.test/admin/services', {
      headers: { Authorization: 'Bearer wrong_key' },
    })
    expect(res.status).toBe(403)
  })

  // ─── Service Management ────────────────────────────────────────────────

  it('creates and lists services', async () => {
    const res = await adminFetch('/admin/services/cloudflare', {
      method: 'PUT',
      body: JSON.stringify({
        baseUrl: 'https://api.cloudflare.com',
        authMethod: 'bearer',
        description: 'Cloudflare API',
      }),
    })
    expect(res.status).toBe(200)
    expect((await res.json() as any).ok).toBe(true)

    const listRes = await adminFetch('/admin/services')
    expect(listRes.status).toBe(200)
    const services = await listRes.json() as any[]
    expect(services.some((s: any) => s.service === 'cloudflare')).toBe(true)
  })

  it('requires baseUrl for service creation', async () => {
    const res = await adminFetch('/admin/services/bad', {
      method: 'PUT',
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  it('creates then deletes services', async () => {
    await setupService('todelete', 'https://example.com')
    const res = await adminFetch('/admin/services/todelete', { method: 'DELETE' })
    expect(res.status).toBe(200)
  })

  // ─── Credential Management ─────────────────────────────────────────────

  it('stores and deletes credentials', async () => {
    await setupService('github', 'https://api.github.com', 'GitHub API')

    // Store
    const storeRes = await adminFetch('/admin/credentials/github', {
      method: 'PUT',
      body: JSON.stringify({
        identity: 'alice',
        token: 'ghp_secret_token_12345',
        metadata: { team: 'backend', env: 'prod' },
      }),
    })
    expect(storeRes.status).toBe(200)
    const body = await storeRes.json() as any
    expect(body.ok).toBe(true)
    expect(body.identity).toBe('alice')

    // Delete
    const delRes = await adminFetch('/admin/credentials/github/alice', { method: 'DELETE' })
    expect(delRes.status).toBe(200)
  })

  it('rejects credential storage for unknown service', async () => {
    const res = await adminFetch('/admin/credentials/nonexistent', {
      method: 'PUT',
      body: JSON.stringify({ identity: 'bob', token: 'xxx' }),
    })
    expect(res.status).toBe(404)
  })

  // ─── Token Minting ─────────────────────────────────────────────────────

  it('mints a scoped token', async () => {
    const res = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({
        grants: [{
          services: 'cloudflare',
          methods: 'GET',
          paths: '/client/v4/',
          metadata: { userId: 'alice' },
          ttl: '1h',
        }],
      }),
    })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.token).toMatch(/^vt_/)
    expect(body.publicKey).toBeTruthy()
  })

  it('rejects mint without grants', async () => {
    const res = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({ grants: [] }),
    })
    expect(res.status).toBe(400)
  })

  // ─── Token Restriction ─────────────────────────────────────────────────

  it('restricts a token (public endpoint)', async () => {
    // Mint a broad token
    const mintRes = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({
        grants: [{ services: ['cloudflare', 'github'], methods: ['GET', 'POST'] }],
      }),
    })
    const { token } = await mintRes.json() as any

    // Restrict it (no admin key needed)
    const res = await SELF.fetch('https://auth-proxy.test/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        constraints: [{ services: 'cloudflare', methods: 'GET', ttl: '10m' }],
      }),
    })
    const body = await res.json() as any
    if (res.status !== 200) {
      console.error('Restrict failed:', body)
    }
    expect(res.status).toBe(200)
    expect(body.token).toMatch(/^vt_/)
    expect(body.token.length).toBeGreaterThan(token.length)
  })

  // ─── Discoverability ──────────────────────────────────────────────────

  it('lists services scoped by admin key', async () => {
    await setupService('cloudflare', 'https://api.cloudflare.com', 'Cloudflare API')
    const res = await fetchWithToken('/services', ADMIN_KEY)
    expect(res.status).toBe(200)
    const body = await res.json() as any[]
    expect(body.length).toBeGreaterThan(0)
  })

  it('lists services scoped by token', async () => {
    await setupService('cloudflare', 'https://api.cloudflare.com')
    await setupService('github', 'https://api.github.com')

    // Mint a token that only allows cloudflare
    const mintRes = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({
        grants: [{ services: 'cloudflare', methods: 'GET' }],
      }),
    })
    const { token } = await mintRes.json() as any

    const res = await fetchWithToken('/services', token)
    expect(res.status).toBe(200)
    const body = await res.json() as any[]
    expect(body.every((s: any) => s.service === 'cloudflare')).toBe(true)
    expect(body.length).toBe(1)
  })

  // ─── Proxy ──────────────────────────────────────────────────────────────

  it('rejects proxy requests without auth', async () => {
    const res = await SELF.fetch('https://auth-proxy.test/proxy/cloudflare/client/v4/zones')
    expect(res.status).toBe(401)
  })

  it('rejects proxy to unknown service', async () => {
    const res = await fetchWithToken('/proxy/nonexistent/test', ADMIN_KEY)
    expect(res.status).toBe(404)
  })

  it('rejects proxy with revoked token', async () => {
    await setupService('cloudflare', 'https://api.cloudflare.com')
    await setupCredential('cloudflare', 'alice', 'cf_fake_token', { userId: 'alice' })

    // Mint a token
    const mintRes = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({
        grants: [{ services: 'cloudflare', methods: 'GET', metadata: { userId: 'alice' } }],
      }),
    })
    const { token } = await mintRes.json() as any

    // Revoke it
    const revokeRes = await adminFetch('/admin/tokens/revoke', {
      method: 'POST',
      body: JSON.stringify({ token, reason: 'test revocation' }),
    })
    const revokeBody = await revokeRes.json() as any
    if (revokeRes.status !== 200) {
      console.error('Revoke failed:', revokeBody)
    }
    expect(revokeRes.status).toBe(200)

    // Try to use it — should be forbidden
    const proxyRes = await fetchWithToken('/proxy/cloudflare/client/v4/zones', token)
    expect(proxyRes.status).toBe(403)
    const body = await proxyRes.json() as any
    expect(body.error).toContain('revoked')
  })

  it('rejects proxy when token scope does not match', async () => {
    await setupService('cloudflare', 'https://api.cloudflare.com')
    await setupCredential('cloudflare', 'alice', 'cf_fake_token', { userId: 'alice' })

    // Mint a token only for GET
    const mintRes = await adminFetch('/admin/tokens/mint', {
      method: 'POST',
      body: JSON.stringify({
        grants: [{
          services: 'cloudflare',
          methods: 'GET',
          paths: '/client/v4/zones',
          metadata: { userId: 'alice' },
        }],
      }),
    })
    const { token } = await mintRes.json() as any

    // Try DELETE — should be forbidden
    const res = await fetchWithToken('/proxy/cloudflare/client/v4/zones/abc', token, {
      method: 'DELETE',
    })
    const body = await res.json() as any
    if (res.status !== 403) {
      console.error('Expected 403, got:', res.status, body)
    }
    expect(res.status).toBe(403)
  })

  // ─── Key Generation ────────────────────────────────────────────────────

  it('generates a key pair', async () => {
    const res = await adminFetch('/admin/keys/generate', { method: 'POST' })
    expect(res.status).toBe(200)
    const body = await res.json() as any
    expect(body.privateKey).toMatch(/^ed25519-private\//)
    expect(body.publicKey).toMatch(/^ed25519\//)
  })
})
