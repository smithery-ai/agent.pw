import { describe, expect, it } from 'vitest'
import { createAgentPw } from 'agent.pw'
import { betterAuthSchema, createAgentPwBetterAuthPlugin } from 'agent.pw/better-auth'
import type { Account } from 'better-auth'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

function makeAccount(overrides: Partial<Account> = {}): Account {
  return {
    id: 'acc_123',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    providerId: 'linear',
    accountId: 'user_123',
    userId: 'auth_user_123',
    accessToken: 'access-token',
    refreshToken: 'refresh-token',
    accessTokenExpiresAt: new Date('2026-01-02T00:00:00.000Z'),
    refreshTokenExpiresAt: new Date('2026-02-02T00:00:00.000Z'),
    idToken: null,
    scope: 'read write',
    password: null,
    ...overrides,
  }
}

describe('Better Auth integration', () => {
  it('exports the Better Auth schema and mirrors provider accounts into credentials', async () => {
    expect(Object.keys(betterAuthSchema).sort()).toEqual([
      'account',
      'session',
      'user',
      'verification',
    ])

    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    })

    await agentPw.profiles.put('/org_alpha/linear', {
      host: ['api.linear.app'],
      oauthConfig: {
        clientId: 'smithery-client',
        tokenUrl: 'https://api.linear.app/oauth/token',
      },
    })

    const plugin = createAgentPwBetterAuthPlugin({
      agentPw,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/org_alpha/linear',
        }
      },
    })
    const initialized = plugin.init?.({} as never)

    await initialized?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)

    expect(await agentPw.credentials.get('/org_alpha/connections/linear_1/linear')).toEqual(
      expect.objectContaining({
        auth: expect.objectContaining({
          kind: 'oauth',
          providerId: 'linear',
          accountId: 'user_123',
        }),
        secret: {
          headers: { Authorization: 'Bearer access-token' },
          oauth: expect.objectContaining({
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            tokenUrl: 'https://api.linear.app/oauth/token',
            clientId: 'smithery-client',
            scopes: 'read write',
          }),
        },
      }),
    )

    await initialized?.options?.databaseHooks?.account?.update?.after?.(
      makeAccount({
        accessToken: 'updated-token',
      }),
      null,
    )

    expect(await agentPw.credentials.get('/org_alpha/connections/linear_1/linear')).toEqual(
      expect.objectContaining({
        secret: expect.objectContaining({
          headers: { Authorization: 'Bearer updated-token' },
          oauth: expect.objectContaining({
            accessToken: 'updated-token',
          }),
        }),
      }),
    )
  })
})
