import { Hono } from 'hono'
import { beforeEach, describe, expect, it } from 'vitest'
import { deriveEncryptionKey } from '@agent.pw/server/crypto'
import { createLogger } from '@agent.pw/server/logger'
import { serviceRoutes } from '../packages/server/src/routes/services'
import {
  BISCUIT_PRIVATE_KEY,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'

let db: TestDb

async function buildApp() {
  const app = new Hono<any>()
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  app.use('*', async (c, next) => {
    c.env = {
      BISCUIT_PRIVATE_KEY,
      ENCRYPTION_KEY: encryptionKey,
    }
    c.set('db', db)
    c.set('logger', createLogger('agentpw').logger)
    return next()
  })
  app.route('/services', serviceRoutes)
  return app
}

function withToken(token: string, headers: Record<string, string> = {}) {
  return { 'Proxy-Authorization': `Bearer ${token}`, ...headers }
}

beforeEach(async () => {
  db = await createTestDb()
})

describe('service routes', () => {
  it('supports create, list, get, and delete flows', async () => {
    const app = await buildApp()
    const managerToken = mintTestToken('org_alpha', ['manage_services'])

    const create = await app.request('https://agent.pw/services/github', {
      method: 'PUT',
      headers: withToken(managerToken, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        allowedHosts: ['api.github.com'],
        authSchemes: [{ type: 'http', scheme: 'bearer' }],
        description: 'GitHub API',
        oauthClientId: 'client-id',
        oauthClientSecret: 'client-secret',
        docsUrl: 'https://docs.github.com',
      }),
    })
    expect(create.status).toBe(200)
    expect(await create.json()).toEqual({ ok: true, slug: 'github' })

    const list = await app.request('https://agent.pw/services', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(list.status).toBe(200)
    expect(await list.json()).toEqual([
      {
        slug: '/github',
        allowedHosts: ['api.github.com'],
        displayName: 'Github',
        description: 'GitHub API',
        docsUrl: 'https://docs.github.com',
      },
    ])

    const detail = await app.request('https://agent.pw/services/github', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(detail.status).toBe(200)
    expect(await detail.json()).toEqual({
      slug: '/github',
      allowedHosts: ['api.github.com'],
      displayName: 'Github',
      description: 'GitHub API',
      docsUrl: 'https://docs.github.com',
      authSchemes: [{ type: 'http', scheme: 'bearer' }],
    })

    const remove = await app.request('https://agent.pw/services/github', {
      method: 'DELETE',
      headers: withToken(managerToken),
    })
    expect(remove.status).toBe(200)
    expect(await remove.json()).toEqual({ ok: true })

    const missing = await app.request('https://agent.pw/services/github', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(missing.status).toBe(404)
  })

  it('rejects reserved slugs, missing rights, and unknown services', async () => {
    const app = await buildApp()

    const forbidden = await app.request('https://agent.pw/services/linear', {
      method: 'PUT',
      headers: withToken(mintTestToken('org_alpha'), { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ allowedHosts: ['api.linear.app'] }),
    })
    expect(forbidden.status).toBe(403)

    const reserved = await app.request('https://agent.pw/services/auth', {
      method: 'PUT',
      headers: withToken(mintTestToken('org_alpha', ['manage_services']), { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ allowedHosts: ['api.auth.app'] }),
    })
    expect(reserved.status).toBe(400)

    const missing = await app.request('https://agent.pw/services/missing', {
      method: 'DELETE',
      headers: withToken(mintTestToken('org_alpha', ['manage_services'])),
    })
    expect(missing.status).toBe(404)

    const createWithoutSecret = await app.request('https://agent.pw/services/plain', {
      method: 'PUT',
      headers: withToken(mintTestToken('org_alpha', ['manage_services']), { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ allowedHosts: ['api.plain.app'] }),
    })
    expect(createWithoutSecret.status).toBe(200)

    const plainDetail = await app.request('https://agent.pw/services/plain', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(plainDetail.status).toBe(200)
    expect(await plainDetail.json()).toEqual({
      slug: '/plain',
      allowedHosts: ['api.plain.app'],
      displayName: 'Plain',
      description: null,
      docsUrl: null,
      authSchemes: null,
    })
  })
})
