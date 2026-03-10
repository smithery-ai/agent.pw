import { Hono } from 'hono'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCoreApp } from '@agent.pw/server'
import { createLogger } from '@agent.pw/server/logger'
import { mintToken } from '@agent.pw/server/biscuit'
import { deriveEncryptionKey } from '@agent.pw/server/crypto'
import { revokeToken } from '@agent.pw/server/db/queries'
import {
  requireRight,
  requireToken,
  resolveUserId,
} from '../packages/server/src/core/middleware'
import {
  BISCUIT_PRIVATE_KEY,
  PUBLIC_KEY_HEX,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'
import { restrictToken } from '@agent.pw/server/biscuit'

let db: TestDb

beforeEach(async () => {
  db = await createTestDb()
})

afterEach(() => {
  vi.restoreAllMocks()
})

function makeUrl(path: string, origin = 'https://agent.pw') {
  return `${origin}${path}`
}

async function buildHarness() {
  const app = new Hono<any>()
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  app.use('*', async (c, next) => {
    c.env = {
      BISCUIT_PRIVATE_KEY: BISCUIT_PRIVATE_KEY,
      ENCRYPTION_KEY: encryptionKey,
    }
    c.set('db', db)
    c.set('logger', createLogger('agentpw').logger)
    return next()
  })
  return app
}

describe('createCoreApp', () => {
  it('serves JWKS and computes BASE_URL from incoming requests', async () => {
    const app = createCoreApp({ db, biscuitPrivateKey: BISCUIT_PRIVATE_KEY })
    app.get('/base-url', c => c.json({ baseUrl: c.env.BASE_URL }))

    const localhost = await app.request(makeUrl('/base-url', 'http://localhost'))
    expect(await localhost.json()).toEqual({ baseUrl: 'http://localhost:3000' })

    const remote = await app.request(makeUrl('/base-url', 'https://vault.example.com'))
    expect(await remote.json()).toEqual({ baseUrl: 'https://vault.example.com' })

    const jwks = await app.request(makeUrl('/.well-known/jwks.json'))
    expect(jwks.status).toBe(200)
    expect(await jwks.json()).toEqual(expect.objectContaining({
      keys: [
        expect.objectContaining({
          kty: 'OKP',
          crv: 'Ed25519',
          kid: 'agentpw-ed25519-1',
        }),
      ],
    }))
  })

  it('returns a 500 response when a route throws', async () => {
    const app = createCoreApp({ db, biscuitPrivateKey: BISCUIT_PRIVATE_KEY })
    app.get('/boom', () => {
      throw new Error('boom')
    })

    const response = await app.request(makeUrl('/boom'))
    expect(response.status).toBe(500)
    expect(await response.json()).toEqual({ error: 'Internal Server Error' })
  })
})

describe('core middleware', () => {
  it('requires valid tokens and exposes token facts on success', async () => {
    const app = await buildHarness()
    app.get('/protected', requireToken, c => c.json(c.get('tokenFacts')))

    const missing = await app.request(makeUrl('/protected'))
    expect(missing.status).toBe(401)

    const invalid = await app.request(makeUrl('/protected'), {
      headers: { 'Proxy-Authorization': 'Bearer bad-token' },
    })
    expect(invalid.status).toBe(401)

    const valid = await app.request(makeUrl('/protected'), {
      headers: { 'Proxy-Authorization': `Bearer ${mintTestToken('org_alpha')}` },
    })
    expect(valid.status).toBe(200)
    expect(await valid.json()).toEqual(expect.objectContaining({
      orgId: 'org_alpha',
      userId: 'org_alpha',
    }))
  })

  it('rejects revoked tokens and service-restricted tokens for management routes', async () => {
    const app = await buildHarness()
    app.get('/protected', requireToken, c => c.json({ ok: true }))

    const token = mintTestToken('org_alpha')
    await revokeToken(db, (await import('@agent.pw/server/biscuit')).getRevocationIds(token, PUBLIC_KEY_HEX)[0], 'revoked')

    const revoked = await app.request(makeUrl('/protected'), {
      headers: { 'Proxy-Authorization': `Bearer ${token}` },
    })
    expect(revoked.status).toBe(403)
    expect(await revoked.json()).toEqual({ error: 'Token has been revoked' })

    const restricted = restrictToken(mintTestToken('org_alpha'), PUBLIC_KEY_HEX, [{ services: 'github' }])
    const forbidden = await app.request(makeUrl('/protected'), {
      headers: { 'Proxy-Authorization': `Bearer ${restricted}` },
    })
    expect(forbidden.status).toBe(403)
    expect(await forbidden.json()).toEqual(expect.objectContaining({ error: 'Forbidden' }))
  })

  it('enforces rights and resolves user identity from tokens', async () => {
    const app = await buildHarness()
    app.get('/needs-admin', requireRight('admin'), c => c.json({ ok: true }))
    app.get('/admin', requireToken, requireRight('admin'), resolveUserId, c => c.json({ userId: c.get('userId') }))
    app.get('/user', requireToken, resolveUserId, c => c.json({ userId: c.get('userId') }))
    app.get('/missing-facts', (c, next) => resolveUserId(c, next), c => c.json({ userId: c.get('userId') }))
    app.get('/identityless', async (c, next) => {
      c.set('tokenFacts', { rights: [], userId: null, orgId: null })
      return resolveUserId(c, next)
    }, c => c.json({ userId: c.get('userId') }))
    app.get('/admin-fallback', async (c, next) => {
      c.set('tokenFacts', { rights: ['admin'], userId: null, orgId: null })
      return resolveUserId(c, next)
    }, c => c.json({ userId: c.get('userId') }))

    const noFacts = await app.request(makeUrl('/needs-admin'))
    expect(noFacts.status).toBe(403)

    const noRight = await app.request(makeUrl('/admin'), {
      headers: { 'Proxy-Authorization': `Bearer ${mintTestToken('org_alpha')}` },
    })
    expect(noRight.status).toBe(403)

    const adminToken = mintToken(BISCUIT_PRIVATE_KEY, 'admin-user', ['admin'])
    const admin = await app.request(makeUrl('/admin'), {
      headers: {
        'Proxy-Authorization': `Bearer ${adminToken}`,
        'Act-As': 'delegated-user',
      },
    })
    expect(admin.status).toBe(200)
    expect(await admin.json()).toEqual({ userId: 'delegated-user' })

    const userToken = mintToken(BISCUIT_PRIVATE_KEY, 'normal-user')
    const sameActAs = await app.request(makeUrl('/user'), {
      headers: {
        'Proxy-Authorization': `Bearer ${userToken}`,
        'Act-As': 'normal-user',
      },
    })
    expect(sameActAs.status).toBe(200)
    expect(await sameActAs.json()).toEqual({ userId: 'normal-user' })

    const differentActAs = await app.request(makeUrl('/user'), {
      headers: {
        'Proxy-Authorization': `Bearer ${userToken}`,
        'Act-As': 'other-user',
      },
    })
    expect(differentActAs.status).toBe(403)

    const missingFacts = await app.request(makeUrl('/missing-facts'))
    expect(missingFacts.status).toBe(403)
    expect(await missingFacts.json()).toEqual({ error: 'Forbidden' })

    const identityless = await app.request(makeUrl('/identityless'))
    expect(identityless.status).toBe(403)
    expect(await identityless.json()).toEqual({ error: 'No identity in token' })

    const adminFallback = await app.request(makeUrl('/admin-fallback'))
    expect(adminFallback.status).toBe(200)
    expect(await adminFallback.json()).toEqual({ userId: 'local' })
  })
})
