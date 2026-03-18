import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { createCoreApp } from '../packages/server/src/core/app'
import {
  mountBrowserAuthRoutes,
  type BrowserSessionTokenChallenge,
} from '../packages/server/src/auth'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

describe('browser auth contract hooks', () => {
  it('mounts optional auth routes around the core app without affecting core routes', async () => {
    const app = createCoreApp({
      db: await createTestDb(),
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      baseUrl: 'http://127.0.0.1:9315',
    })

    const authRoutes = new Hono()
    authRoutes.post('/session-token', (c) =>
      c.json<BrowserSessionTokenChallenge>(
        {
          error: 'Sign in to that instance first.',
          loginUrl: 'http://127.0.0.1:9315/auth/login',
        },
        401,
      ),
    )

    mountBrowserAuthRoutes(app, authRoutes)

    const challenge = await app.request('http://127.0.0.1:9315/auth/session-token', {
      method: 'POST',
    })
    expect(challenge.status).toBe(401)
    expect(await challenge.json()).toEqual({
      error: 'Sign in to that instance first.',
      loginUrl: 'http://127.0.0.1:9315/auth/login',
    })

    const jwks = await app.request('http://127.0.0.1:9315/.well-known/jwks.json')
    expect(jwks.status).toBe(200)
  })
})
