import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCoreApp } from '@agent.pw/server'
import { sql } from 'drizzle-orm'
import {
  encryptCredentials,
  buildCredentialHeaders,
  deriveEncryptionKey,
} from '@agent.pw/server/crypto'
import { upsertCredential } from '@agent.pw/server/db/queries'
import {
  BISCUIT_PRIVATE_KEY,
  ORG_TOKEN,
  ROOT_TOKEN,
  TEST_ORG_ID,
  createTestDb,
  type TestDb,
} from './setup'

let db: TestDb
let app: ReturnType<typeof createCoreApp>

beforeEach(async () => {
  db = await createTestDb()
  app = createCoreApp({
    db,
    biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    baseUrl: 'https://agent.pw',
    cliAuthBaseUrl: 'https://agent.pw',
  })
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function req(path: string, init?: RequestInit) {
  const url = path.startsWith('http') ? path : `https://agent.pw${path}`
  return app.request(url, init)
}

function withProxyToken(token: string, headers: Record<string, string> = {}) {
  return { 'Proxy-Authorization': `Bearer ${token}`, ...headers }
}

function withManagementToken(token: string, headers: Record<string, string> = {}) {
  return { Authorization: `Bearer ${token}`, ...headers }
}

function mgmtReq(path: string, init: RequestInit = {}) {
  return req(path, {
    ...init,
    headers: { ...withManagementToken(ROOT_TOKEN), ...init.headers },
  })
}

function credReq(path: string, init: RequestInit = {}) {
  return req(path, {
    ...init,
    headers: { ...withManagementToken(ORG_TOKEN), ...init.headers },
  })
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function mockUpstream(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>,
) {
  const fetchMock = vi.fn(handler)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function registerProfile(slug: string, body: Record<string, unknown>) {
  const res = await mgmtReq(`/cred_profiles/${slug}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      path: `/${TEST_ORG_ID}/${slug}`,
      ...body,
    }),
  })
  expect(res.status).toBe(200)
}

async function storeCredential(slug: string, body: Record<string, unknown>) {
  const res = await credReq(`/credentials/${slug}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  expect(res.status).toBe(200)
}

async function storeScopedCredential(slug: string, host: string, bearerToken: string) {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const encrypted = await encryptCredentials(encryptionKey, {
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, bearerToken),
  })

  await upsertCredential(db, {
    host,
    path: `/${TEST_ORG_ID}/${slug}`,
    auth: { kind: 'headers' },
    secret: encrypted,
  })
}

describe('Core Scenario Flows', () => {
  it('normalizes legacy string hosts to arrays in credential profile responses', async () => {
    await db.execute(sql`
      INSERT INTO agentpw.cred_profiles (path, host, display_name)
      VALUES ('/legacy', '"api.legacy.example"'::jsonb, 'Legacy')
    `)

    await db.execute(sql`
      INSERT INTO agentpw.cred_profiles (path, host, display_name)
      VALUES ('/null-host', 'null'::jsonb, 'NullHost')
    `)

    const listed = await mgmtReq('/cred_profiles')
    expect(listed.status).toBe(200)
    const { data: profiles } = await listed.json() as { data: unknown[] }
    expect(profiles).toContainEqual(expect.objectContaining({
      slug: '/legacy',
      host: ['api.legacy.example'],
    }))
    const { data: profiles2 } = await mgmtReq('/cred_profiles').then(r => r.json()) as { data: unknown[] }
    expect(profiles2).toContainEqual(expect.objectContaining({
      slug: '/null-host',
      host: [],
    }))

    const detail = await mgmtReq('/cred_profiles/legacy')
    expect(detail.status).toBe(200)
    expect(await detail.json()).toMatchObject({
      slug: '/legacy',
      host: ['api.legacy.example'],
    })

    const nullDetail = await mgmtReq('/cred_profiles/null-host')
    expect(nullDetail.status).toBe(200)
    expect(await nullDetail.json()).toMatchObject({
      slug: '/null-host',
      host: [],
    })
  })

  it('stores credential profiles and credentials through the core API and reports health counts', async () => {
    await registerProfile('github', {
      host: ['api.github.com'],
      displayName: 'GitHub',
      auth: {
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
      },
    })

    await storeCredential('github', {
      token: 'ghp_test123',
      host: 'api.github.com',
      path: `/${TEST_ORG_ID}/github`,
    })

    const health = await req('/')
    expect(health.status).toBe(200)
    expect(await health.json()).toEqual({
      profiles: [{ slug: `/${TEST_ORG_ID}/github`, credentialCount: 1 }],
    })

    const profiles = await mgmtReq('/cred_profiles')
    expect(((await profiles.json()) as { data: unknown[] }).data).toHaveLength(1)

    const creds = await credReq('/credentials')
    expect(((await creds.json()) as { data: unknown[] }).data).toHaveLength(1)
  })

  it('returns auth schemes and managed OAuth readiness in credential profile responses', async () => {
    await registerProfile('linear', {
      host: ['api.linear.app'],
      displayName: 'Linear',
      auth: {
        authSchemes: [{
          type: 'oauth2',
          authorizeUrl: 'https://linear.app/oauth/authorize',
          tokenUrl: 'https://api.linear.app/oauth/token',
        }],
      },
      managedOauth: {
        clientId: 'linear-client-id',
      },
    })

    const listed = await mgmtReq('/cred_profiles')
    expect(listed.status).toBe(200)
    expect(((await listed.json()) as { data: unknown[] }).data).toContainEqual(
      expect.objectContaining({
        slug: `/${TEST_ORG_ID}/linear`,
        authSchemes: [{
          type: 'oauth2',
          authorizeUrl: 'https://linear.app/oauth/authorize',
          tokenUrl: 'https://api.linear.app/oauth/token',
        }],
        managedOauthConfigured: true,
      }),
    )

    const detail = await mgmtReq(`/cred_profiles/linear?path=${encodeURIComponent(`/${TEST_ORG_ID}/linear`)}`)
    expect(detail.status).toBe(200)
    expect(await detail.json()).toMatchObject({
      slug: `/${TEST_ORG_ID}/linear`,
      authSchemes: [{
        type: 'oauth2',
        authorizeUrl: 'https://linear.app/oauth/authorize',
        tokenUrl: 'https://api.linear.app/oauth/token',
      }],
      managedOauthConfigured: true,
    })
  })

  it('injects stored credentials on proxied requests and lets callers override Authorization', async () => {
    await registerProfile('github', {
      host: ['api.github.com'],
      displayName: 'GitHub',
      auth: {
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
      },
    })
    await storeCredential('github', {
      token: 'ghp_test123',
      host: 'api.github.com',
      path: `/${TEST_ORG_ID}/github`,
    })

    const fetchMock = mockUpstream(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ authorization: headers.get('Authorization') })
    })

    const injected = await req('/proxy/api.github.com/user', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(injected.status).toBe(200)
    expect(await injected.json()).toEqual({ authorization: 'Bearer ghp_test123' })

    const explicit = await req('/proxy/api.github.com/user', {
      headers: withProxyToken(ORG_TOKEN, { Authorization: 'Bearer caller-specified' }),
    })
    expect(explicit.status).toBe(200)
    expect(await explicit.json()).toEqual({ authorization: 'Bearer caller-specified' })

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('surfaces bootstrap hints on 401s and blocks private targets before proxying', async () => {
    await registerProfile('github', {
      host: ['api.github.com'],
      displayName: 'GitHub',
      auth: {
        authSchemes: [
          {
            type: 'oauth2',
            authorizeUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            scopes: 'repo read:user',
          },
        ],
      },
    })

    mockUpstream(async () => new Response('unauthorized', { status: 401 }))

    const bootstrap = await req('/proxy/api.github.com/user', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(bootstrap.status).toBe(401)
    expect(bootstrap.headers.get('www-authenticate')).toContain('AgentPW')
    expect(bootstrap.headers.get('www-authenticate')).toContain(`profile="/${TEST_ORG_ID}/github"`)
    expect(bootstrap.headers.get('www-authenticate')).toContain('target_host="api.github.com"')
    expect(bootstrap.headers.get('www-authenticate')).toMatch(
      /authorization_uri="https:\/\/agent\.pw\/auth\/github\?flow_id=[0-9a-f]+"/,
    )

    const privateTarget = await req('/proxy/127.0.0.1/admin', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(privateTarget.status).toBe(403)
  })

  it('selects policy-gated credentials and enforces restrict and revoke token routes', async () => {
    await registerProfile('linear', {
      host: ['api.linear.app'],
      displayName: 'Linear',
      auth: {
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
      },
    })

    await storeScopedCredential(
      'linear-policy',
      'api.linear.app',
      'lin_api_test',
    )

    mockUpstream(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ authorization: headers.get('Authorization') })
    })

    const proxied = await req('/proxy/api.linear.app/graphql', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(proxied.status).toBe(200)
    expect(await proxied.json()).toEqual({ authorization: 'Bearer lin_api_test' })

    const issuedRes = await req('/tokens', {
      method: 'POST',
      headers: withManagementToken(ORG_TOKEN, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        constraints: [{ services: 'api.linear.app', methods: 'GET', paths: '/graphql' }],
      }),
    })
    expect(issuedRes.status).toBe(200)
    const issued = (await issuedRes.json()) as {
      id: string
      token: string
      expiresAt: string | null
      lastUsedAt: string | null
    }
    expect(issued.token).toMatch(/^apw_/)
    expect(issued.lastUsedAt).toBeNull()

    const listedBeforeUse = await req('/tokens', {
      headers: withManagementToken(ORG_TOKEN),
    })
    expect(listedBeforeUse.status).toBe(200)
    expect(await listedBeforeUse.json()).toEqual({
      data: [
        expect.objectContaining({
          id: issued.id,
          lastUsedAt: null,
        }),
      ],
    })

    const restrictedGet = await req('/proxy/api.linear.app/graphql', {
      headers: withProxyToken(issued.token),
    })
    expect(restrictedGet.status).toBe(200)

    const restrictedPost = await req('/proxy/api.linear.app/graphql', {
      method: 'POST',
      headers: withProxyToken(issued.token),
    })
    expect(restrictedPost.status).toBe(403)

    const restrictedMint = await req('/tokens', {
      method: 'POST',
      headers: withManagementToken(issued.token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ constraints: [{ ttl: '5m' }] }),
    })
    expect(restrictedMint.status).toBe(403)

    const fetchedAfterUse = await req(`/tokens/${issued.id}`, {
      headers: withManagementToken(ORG_TOKEN),
    })
    expect(fetchedAfterUse.status).toBe(200)
    expect(await fetchedAfterUse.json()).toEqual(
      expect.objectContaining({
        id: issued.id,
        lastUsedAt: expect.any(String),
      }),
    )

    const revoked = await req(`/tokens/${issued.id}`, {
      method: 'DELETE',
      headers: withManagementToken(ORG_TOKEN, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ reason: 'no longer needed' }),
    })
    expect(revoked.status).toBe(200)

    const revokedChildProxy = await req('/proxy/api.linear.app/graphql', {
      headers: withProxyToken(issued.token),
    })
    expect(revokedChildProxy.status).toBe(403)

    const parentStillWorks = await req('/proxy/api.linear.app/graphql', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(parentStillWorks.status).toBe(200)
  })

  it('requires an explicit credential name when multiple credentials match a host', async () => {
    await registerProfile('slack', {
      host: ['slack.com'],
      displayName: 'Slack',
      auth: {
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
      },
    })

    await storeScopedCredential('shared-slack', 'slack.com', 'xoxb-shared')
    await storeScopedCredential('personal-slack', 'slack.com', 'xoxb-personal')

    mockUpstream((_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({
        authorization: headers.get('Authorization'),
      })
    })

    const ambiguous = await req('/proxy/slack.com/api/auth.test', {
      headers: withProxyToken(ORG_TOKEN),
    })
    expect(ambiguous.status).toBe(409)
    expect(await ambiguous.json()).toMatchObject({
      credentialNames: expect.arrayContaining(['shared-slack', 'personal-slack']),
    })

    const selected = await req('/proxy/slack.com/api/auth.test', {
      headers: withProxyToken(ORG_TOKEN, { 'agentpw-credential': 'personal-slack' }),
    })
    expect(selected.status).toBe(200)
    expect(await selected.json()).toEqual({
      authorization: 'Bearer xoxb-personal',
    })
  })
})
