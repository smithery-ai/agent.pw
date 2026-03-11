import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { deriveEncryptionKey } from '@agent.pw/server/crypto'
import { createLogger } from '@agent.pw/server/logger'
import { serviceRoutes } from '../packages/server/src/routes/services'
import * as queryModule from '../packages/server/src/db/queries'
import {
  BISCUIT_PRIVATE_KEY,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'

let db: TestDb

interface ListResponse<T> {
  data: T[]
  hasMore: boolean
  nextCursor: string | null
}

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
    const managerToken = mintTestToken('org_alpha', ['profile.manage'])

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
    expect(await list.json()).toEqual({
      data: [
        {
          slug: '/github',
          allowedHosts: ['api.github.com'],
          displayName: 'Github',
          description: 'GitHub API',
          docsUrl: 'https://docs.github.com',
        },
      ],
      hasMore: false,
      nextCursor: null,
    })

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
      headers: withToken(mintTestToken('org_alpha', ['profile.manage']), { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ allowedHosts: ['api.auth.app'] }),
    })
    expect(reserved.status).toBe(400)

    const missing = await app.request('https://agent.pw/services/missing', {
      method: 'DELETE',
      headers: withToken(mintTestToken('org_alpha', ['profile.manage'])),
    })
    expect(missing.status).toBe(404)

    const createWithoutSecret = await app.request('https://agent.pw/services/plain', {
      method: 'PUT',
      headers: withToken(mintTestToken('org_alpha', ['profile.manage']), { 'Content-Type': 'application/json' }),
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

  it('paginates legacy service listings and rejects malformed cursors', async () => {
    const app = await buildApp()
    const managerToken = mintTestToken('org_alpha', ['profile.manage'])

    for (const slug of ['github', 'gitlab']) {
      const res = await app.request(`https://agent.pw/services/${slug}`, {
        method: 'PUT',
        headers: withToken(managerToken, { 'Content-Type': 'application/json' }),
        body: JSON.stringify({ allowedHosts: [`api.${slug}.com`] }),
      })
      expect(res.status).toBe(200)
    }

    const first = await app.request('https://agent.pw/services?limit=1', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(first.status).toBe(200)
    const firstPage = (await first.json()) as ListResponse<{ slug: string }>
    expect(firstPage.data).toEqual([
      expect.objectContaining({ slug: '/github' }),
    ])
    expect(firstPage.hasMore).toBe(true)
    expect(firstPage.nextCursor).toBeTruthy()

    const second = await app.request(`https://agent.pw/services?limit=1&cursor=${encodeURIComponent(firstPage.nextCursor!)}`, {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(second.status).toBe(200)
    expect((await second.json()) as ListResponse<{ slug: string }>).toEqual({
      data: [expect.objectContaining({ slug: '/gitlab' })],
      hasMore: false,
      nextCursor: null,
    })

    const invalid = await app.request('https://agent.pw/services?cursor=bad-cursor', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(invalid.status).toBe(400)
    expect(await invalid.json()).toEqual({ error: 'Invalid pagination cursor' })
  })

  it('re-throws non-pagination errors from service list', async () => {
    const app = await buildApp()
    const spy = vi.spyOn(queryModule, 'listServicesPage').mockRejectedValueOnce(new Error('unexpected error'))

    const res = await app.request('https://agent.pw/services', {
      headers: withToken(mintTestToken('org_alpha')),
    })
    expect(res.status).toBe(500)

    spy.mockRestore()
  })
})
