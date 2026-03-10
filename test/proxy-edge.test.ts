import { Hono } from 'hono'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCoreApp } from '@agent.pw/server'
import { deriveEncryptionKey, decryptCredentials, encryptCredentials } from '@agent.pw/server/crypto'
import { createLogger } from '@agent.pw/server/logger'
import { extractBearerToken, handleProxy } from '@agent.pw/server/proxy'
import {
  getCredential,
  upsertCredProfile,
  upsertCredential,
} from '@agent.pw/server/db/queries'
import {
  BISCUIT_PRIVATE_KEY,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'

let db: TestDb

beforeEach(async () => {
  db = await createTestDb()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function withToken(token: string, headers: Record<string, string> = {}) {
  return { 'Proxy-Authorization': `Bearer ${token}`, ...headers }
}

async function createApp(cliAuthBaseUrl = 'https://agent.pw') {
  return createCoreApp({
    db,
    biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    baseUrl: 'https://agent.pw',
    cliAuthBaseUrl,
  })
}

async function storeOAuthCredential(host: string, path: string, accessToken: string, expiresAt?: string, refreshToken = 'refresh-token') {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const secret = await encryptCredentials(encryptionKey, {
    headers: { Authorization: `Bearer ${accessToken}` },
    oauth: {
      accessToken,
      refreshToken,
      tokenUrl: 'https://oauth.example.com/token',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      scopes: 'repo',
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    },
  })

  await upsertCredential(db, {
    host,
    path,
    auth: { kind: 'headers' },
    secret,
  })
}

async function createManualProxyApp() {
  const app = new Hono<any>()
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  app.use('*', async (c, next) => {
    c.env = {
      BISCUIT_PRIVATE_KEY,
      ENCRYPTION_KEY: encryptionKey,
      CLI_AUTH_BASE_URL: 'https://agent.pw',
    }
    c.set('db', db)
    c.set('logger', createLogger('agentpw').logger)
    return next()
  })
  return app
}

describe('proxy routes and proxy handler edges', () => {
  it('extracts bearer tokens with and without the Bearer prefix', () => {
    expect(extractBearerToken(undefined)).toBeNull()
    expect(extractBearerToken('Bearer prefixed-token')).toBe('prefixed-token')
    expect(extractBearerToken('raw-token')).toBe('raw-token')
  })

  it('parses explicit profile routes and rejects missing hostnames', async () => {
    const app = await createApp()
    await upsertCredProfile(db, '/github', {
      host: ['api.github.com'],
      auth: { authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await upsertCredential(db, {
      host: 'api.github.com',
      path: '/orgs/org_alpha/github',
      auth: { kind: 'headers' },
      secret: await encryptCredentials(await deriveEncryptionKey(BISCUIT_PRIVATE_KEY), {
        headers: { Authorization: 'Bearer gh-token' },
      }),
    })

    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({ authorization: headers.get('Authorization') }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const missing = await app.request('https://agent.pw/proxy/', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(missing.status).toBe(400)

    const explicit = await app.request('https://agent.pw/proxy/github/api.github.com/user', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(explicit.status).toBe(200)
    expect(await explicit.json()).toEqual({ authorization: 'Bearer gh-token' })
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.github.com/user')

    const rootPath = await app.request('https://agent.pw/proxy/api.github.com', {
      headers: withToken(mintTestToken('org_alpha'), { 'agentpw-credential': 'github' }),
    })
    expect(rootPath.status).toBe(200)
    expect(fetchMock.mock.calls[1]?.[0]).toBe('https://api.github.com/')
  })

  it('handles missing tokens, invalid selectors, unknown profiles, and host mismatches', async () => {
    const app = await createApp()
    await upsertCredProfile(db, '/github', {
      host: ['api.github.com'],
      auth: { authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await upsertCredential(db, {
      host: 'api.github.com',
      path: '/orgs/org_beta/foreign',
      auth: { kind: 'headers' },
      secret: await encryptCredentials(await deriveEncryptionKey(BISCUIT_PRIVATE_KEY), {
        headers: { Authorization: 'Bearer foreign-token' },
      }),
    })

    const missingToken = await app.request('https://agent.pw/proxy/api.github.com/user')
    expect(missingToken.status).toBe(401)

    const invalidToken = await app.request('https://agent.pw/proxy/api.github.com/user', {
      headers: withToken('bad-token'),
    })
    expect(invalidToken.status).toBe(401)

    const selectorApp = await createManualProxyApp()
    selectorApp.get('/selector', c => handleProxy(c, undefined, 'api.github.com', '/user'))
    selectorApp.get('/missing-profile', c => handleProxy(c, 'missing', 'api.github.com', '/user'))
    selectorApp.get('/wrong-host', c => handleProxy(c, 'github', 'api.gitlab.com', '/user'))

    const invalidSelector = await selectorApp.request('https://agent.pw/selector', {
      headers: withToken(mintTestToken('org_alpha'), { 'agentpw-credential': '/' }),
    })
    expect(invalidSelector.status).toBe(400)

    const forbiddenSelector = await selectorApp.request('https://agent.pw/selector', {
      headers: withToken(mintTestToken('org_alpha'), { 'agentpw-credential': '/orgs/org_beta/foreign' }),
    })
    expect(forbiddenSelector.status).toBe(403)

    const missingProfile = await selectorApp.request('https://agent.pw/missing-profile', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(missingProfile.status).toBe(404)

    const wrongHost = await selectorApp.request('https://agent.pw/wrong-host', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(wrongHost.status).toBe(403)
  })

  it('refreshes OAuth credentials, forwards request bodies, and strips proxy-only headers', async () => {
    const app = await createApp()
    const token = mintTestToken('org_alpha')
    await storeOAuthCredential(
      'api.refresh.com',
      '/orgs/org_alpha/oauth-service',
      'old-access',
      new Date(Date.now() + 60_000).toISOString(),
    )

    const fetchMock = vi.fn(async (input, init) => {
      if (String(input) === 'https://oauth.example.com/token') {
        return new Response(JSON.stringify({
          access_token: 'new-access',
          refresh_token: 'new-refresh',
          expires_in: 300,
        }), {
          headers: { 'content-type': 'application/json' },
        })
      }

      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({
        authorization: headers.get('Authorization'),
        proxyAuthorization: headers.get('Proxy-Authorization'),
        selector: headers.get('agentpw-credential'),
        actAs: headers.get('Act-As'),
        method: init?.method,
        body: init?.body ? await new Response(init.body).text() : null,
      }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const response = await app.request('https://agent.pw/proxy/api.refresh.com/submit?mode=1', {
      method: 'POST',
      headers: withToken(token, {
        'Content-Type': 'application/json',
        'agentpw-credential': 'oauth-service',
        'Act-As': 'someone-else',
      }),
      body: JSON.stringify({ ok: true }),
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      authorization: 'Bearer new-access',
      proxyAuthorization: null,
      selector: null,
      actAs: null,
      method: 'POST',
      body: '{"ok":true}',
    })

    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const stored = await getCredential(db, 'api.refresh.com', '/orgs/org_alpha/oauth-service')
    expect(stored).not.toBeNull()
    expect(await decryptCredentials(encryptionKey, stored!.secret)).toEqual(expect.objectContaining({
      headers: { Authorization: 'Bearer new-access' },
      oauth: expect.objectContaining({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      }),
    }))
  })

  it('skips OAuth refresh when the stored access token is still fresh', async () => {
    const app = await createApp()
    const token = mintTestToken('org_alpha')
    await storeOAuthCredential(
      'api.refresh.com',
      '/orgs/org_alpha/oauth-service',
      'still-valid',
      new Date(Date.now() + 15 * 60_000).toISOString(),
    )

    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({
        authorization: headers.get('Authorization'),
      }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const response = await app.request('https://agent.pw/proxy/api.refresh.com', {
      headers: withToken(token, {
        'agentpw-credential': 'oauth-service',
      }),
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ authorization: 'Bearer still-valid' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.refresh.com/')
  })

  it('treats invalid OAuth expiry timestamps as non-refreshable', async () => {
    const app = await createApp()
    const token = mintTestToken('org_alpha')
    await storeOAuthCredential(
      'api.refresh.com',
      '/orgs/org_alpha/oauth-service',
      'invalid-expiry',
      'not-a-date',
    )

    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({
        authorization: headers.get('Authorization'),
      }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const response = await app.request('https://agent.pw/proxy/api.refresh.com/user', {
      headers: withToken(token, {
        'agentpw-credential': 'oauth-service',
      }),
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ authorization: 'Bearer invalid-expiry' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.refresh.com/user')
  })

  it('does not refresh OAuth credentials when no expiry is stored', async () => {
    const app = await createApp()
    const token = mintTestToken('org_alpha')
    await storeOAuthCredential(
      'api.refresh.com',
      '/orgs/org_alpha/oauth-service',
      'missing-expiry',
      undefined,
    )

    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({
        authorization: headers.get('Authorization'),
      }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const response = await app.request('https://agent.pw/proxy/api.refresh.com/user', {
      headers: withToken(token, {
        'agentpw-credential': 'oauth-service',
      }),
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ authorization: 'Bearer missing-expiry' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('surfaces OAuth refresh failures plus DNS and generic upstream failures', async () => {
    const app = await createApp()
    const token = mintTestToken('org_alpha')
    await storeOAuthCredential(
      'api.refresh.com',
      '/orgs/org_alpha/oauth-service',
      'old-access',
      new Date(Date.now() + 60_000).toISOString(),
    )

    vi.stubGlobal('fetch', vi.fn(async () => new Response('bad token', { status: 400 })))

    const refreshFailure = await app.request('https://agent.pw/proxy/api.refresh.com/user', {
      headers: withToken(token),
    })
    expect(refreshFailure.status).toBe(401)
    expect(await refreshFailure.json()).toEqual(expect.objectContaining({
      error: expect.stringContaining('OAuth token refresh failed'),
    }))

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('getaddrinfo ENOTFOUND api.down.example')
    }))

    const dnsFailure = await app.request('https://agent.pw/proxy/api.down.example/user', {
      headers: withToken(token),
    })
    expect(dnsFailure.status).toBe(502)
    expect(await dnsFailure.json()).toEqual({
      error: 'DNS resolution failed for api.down.example',
      hint: 'The hostname does not resolve. Verify the service URL is correct.',
    })

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('socket hang up')
    }))

    const headFailure = await app.request('https://agent.pw/proxy/api.fail.example/user', {
      method: 'HEAD',
      headers: withToken(token),
    })
    expect(headFailure.status).toBe(502)

    const genericFailure = await app.request('https://agent.pw/proxy/api.fail.example/user', {
      method: 'GET',
      headers: withToken(token),
    })
    expect(genericFailure.status).toBe(502)
    expect(await genericFailure.json()).toEqual({
      error: 'Failed to reach upstream: socket hang up',
      hint: 'Could not connect to api.fail.example. The service may be down or unreachable.',
    })

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw 'plain upstream failure'
    }))

    const stringFailure = await app.request('https://agent.pw/proxy/api.fail.example/user', {
      method: 'GET',
      headers: withToken(token),
    })
    expect(stringFailure.status).toBe(502)
    expect(await stringFailure.json()).toEqual({
      error: 'Failed to reach upstream: plain upstream failure',
      hint: 'Could not connect to api.fail.example. The service may be down or unreachable.',
    })

    const linkLocal = await app.request('https://agent.pw/proxy/169.254.1.1/user', {
      headers: withToken(token),
    })
    expect(linkLocal.status).toBe(403)

    const privateRange = await app.request('https://agent.pw/proxy/172.16.0.1/user', {
      headers: withToken(token),
    })
    expect(privateRange.status).toBe(403)

    const privateNetwork = await app.request('https://agent.pw/proxy/192.168.1.1/user', {
      headers: withToken(token),
    })
    expect(privateNetwork.status).toBe(403)

    const tenNet = await app.request('https://agent.pw/proxy/10.0.0.1/user', {
      headers: withToken(token),
    })
    expect(tenNet.status).toBe(403)

    const zeroNet = await app.request('https://agent.pw/proxy/0.0.0.0/user', {
      headers: withToken(token),
    })
    expect(zeroNet.status).toBe(403)

    const linkLocalV6 = await app.request('https://agent.pw/proxy/fe80::1/user', {
      headers: withToken(token),
    })
    expect(linkLocalV6.status).toBe(403)

    const uniqueLocalFc = await app.request('https://agent.pw/proxy/fc00::1/user', {
      headers: withToken(token),
    })
    expect(uniqueLocalFc.status).toBe(403)

    const uniqueLocalFd = await app.request('https://agent.pw/proxy/fd00::1/user', {
      headers: withToken(token),
    })
    expect(uniqueLocalFd.status).toBe(403)
  })

  it('adds bootstrap challenges without authorization URIs when CLI auth is disabled', async () => {
    const app = await createApp('')
    await upsertCredProfile(db, '/notion', {
      host: ['api.notion.so'],
      auth: { authSchemes: [{ type: 'oauth2', authorizeUrl: 'https://notion.so/oauth/authorize', tokenUrl: 'https://notion.so/oauth/token' }] },
    })

    vi.stubGlobal('fetch', vi.fn(async () => new Response('unauthorized', { status: 401 })))

    const response = await app.request('https://agent.pw/proxy/api.notion.so/v1/users', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('AgentPW target_host="api.notion.so", profile="/notion"')
  })

  it('adds a manual authorization URI when no profile matches the upstream host', async () => {
    const app = await createApp()

    vi.stubGlobal('fetch', vi.fn(async () => new Response('unauthorized', { status: 401 })))

    const response = await app.request('https://agent.pw/proxy/api.unknown.example/v1/me', {
      headers: withToken(mintTestToken('org_alpha')),
    })

    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(
      'AgentPW target_host="api.unknown.example", authorization_uri="https://agent.pw/auth/login?return_to=%2Fauth%2Fmanual%3Ftarget%3Dapi.unknown.example"',
    )
  })
})
