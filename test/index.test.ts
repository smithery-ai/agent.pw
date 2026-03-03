import { describe, it, expect, beforeEach } from 'vitest'
import { createApp } from '../src/index'
import {
  createTestDb,
  BISCUIT_PRIVATE_KEY,
  BASE_URL,
  mintRootToken,
  mintProxyToken,
  type TestDb,
} from './setup'
import { mintToken } from '../src/biscuit'

let db: TestDb
let app: ReturnType<typeof createApp>

beforeEach(async () => {
  db = await createTestDb()
  app = createApp({ db, biscuitPrivateKey: BISCUIT_PRIVATE_KEY, baseUrl: BASE_URL })
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

async function seedVault(slug = 'personal') {
  await mgmtReq('/vaults', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ slug, displayName: slug }),
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
      supportedAuthMethods: ['oauth', 'api_key'],
      apiType: 'rest',
      docsUrl: 'https://docs.github.com/en/rest',
    }),
  })
}

// ─── Health ──────────────────────────────────────────────────────────────────

describe('Health', () => {
  it('GET / returns ok', async () => {
    const res = await req('/')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({ status: 'ok', service: 'warden' })
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
    const res = await req('/vaults', {
      headers: { Authorization: 'Bearer invalid_token' },
    })
    expect(res.status).toBe(401)
  })

  it('accepts requests with valid management token', async () => {
    const res = await mgmtReq('/services', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(200)
  })
})

// ─── Vault Management ────────────────────────────────────────────────────────

describe('Vault Management', () => {
  it('creates a vault', async () => {
    const res = await mgmtReq('/vaults', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug: 'team-alpha', displayName: 'Team Alpha' }),
    })
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    expect(body.ok).toBe(true)
  })

  it('lists vaults', async () => {
    await seedVault('personal')
    await seedVault('team-alpha')
    const res = await mgmtReq('/vaults')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(2)
  })

  it('deletes a vault', async () => {
    await seedVault('to-delete')
    const res = await mgmtReq('/vaults/to-delete', { method: 'DELETE' })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/vaults')
    const body = (await list.json()) as any[]
    expect(body.find((v: any) => v.slug === 'to-delete')).toBeUndefined()
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

  it('deletes a service', async () => {
    await seedService()
    const res = await mgmtReq('/services/api.github.com', { method: 'DELETE' })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/services')
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })
})

// ─── Credential Management (vault-scoped) ────────────────────────────────────

describe('Credential Management', () => {
  beforeEach(async () => {
    await seedVault('personal')
    await seedService()
  })

  it('stores a credential in a vault', async () => {
    const res = await mgmtReq('/vaults/personal/credentials/api.github.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123', identity: 'alice' }),
    })
    expect(res.status).toBe(200)
  })

  it('lists credentials in a vault', async () => {
    await mgmtReq('/vaults/personal/credentials/api.github.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq('/vaults/personal/credentials')
    expect(res.status).toBe(200)
    const body = (await res.json()) as any[]
    expect(body).toHaveLength(1)
    expect(body[0].service).toBe('api.github.com')
    expect(body[0].hasToken).toBe(true)
  })

  it('rejects credential for non-existent service', async () => {
    const res = await mgmtReq('/vaults/personal/credentials/nonexistent', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'test' }),
    })
    expect(res.status).toBe(404)
  })

  it('rejects credential for non-existent vault', async () => {
    const res = await mgmtReq('/vaults/nonexistent/credentials/api.github.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'test' }),
    })
    expect(res.status).toBe(404)
  })

  it('deletes a credential', async () => {
    await mgmtReq('/vaults/personal/credentials/api.github.com', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'ghp_test123' }),
    })

    const res = await mgmtReq('/vaults/personal/credentials/api.github.com', {
      method: 'DELETE',
    })
    expect(res.status).toBe(200)

    const list = await mgmtReq('/vaults/personal/credentials')
    const body = (await list.json()) as any[]
    expect(body).toHaveLength(0)
  })
})

// ─── Token Minting ──────────────────────────────────────────────────────────

describe('Token Minting', () => {
  it('mints a proxy token with grants format', async () => {
    const res = await mgmtReq('/tokens/mint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grants: [{ services: 'api.github.com', vault: 'personal' }],
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
        bindings: { 'api.github.com': { vault: 'personal' } },
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
        vaultAdmin: ['personal'],
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
})

// ─── Discovery (content-negotiated) ──────────────────────────────────────────

describe('Discovery', () => {
  beforeEach(async () => {
    await seedService()
  })

  it('returns 401 JSON for unauthenticated agent', async () => {
    const res = await req('/api.github.com', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toBe('Bearer realm="warden"')

    const body = (await res.json()) as any
    expect(body.service).toBe('GitHub')
    expect(body.canonical).toBe('api.github.com')
    expect(body.auth_options).toHaveLength(2)
    expect(body.auth_options[0].type).toBe('oauth')
    expect(body.auth_options[1].type).toBe('api_key')
  })

  it('returns HTML for unauthenticated browser', async () => {
    const res = await req('/api.github.com', {
      headers: { Accept: 'text/html' },
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain('GitHub')
    expect(text).toContain('Connect with OAuth')
    expect(text).toContain('Enter API Key')
  })

  it('returns 200 JSON for authenticated agent', async () => {
    const token = mintProxyToken('api.github.com', 'personal')

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

  it('returns 404 for unknown service', async () => {
    const res = await req('/unknown.api.com', {
      headers: { Accept: 'application/json' },
    })
    expect(res.status).toBe(404)
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
})

// ─── Legacy Redirect ────────────────────────────────────────────────────────

describe('Legacy Redirect', () => {
  it('redirects /proxy/:service/* to /:service/*', async () => {
    const res = await req('/proxy/api.github.com/user', { redirect: 'manual' })
    expect(res.status).toBe(301)
    expect(res.headers.get('Location')).toBe('/api.github.com/user')
  })
})

// ─── Auth Flow Polling ──────────────────────────────────────────────────────

describe('Auth Flow Polling', () => {
  it('returns 404 for unknown flow', async () => {
    const res = await req('/auth/status/nonexistent')
    expect(res.status).toBe(404)
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
