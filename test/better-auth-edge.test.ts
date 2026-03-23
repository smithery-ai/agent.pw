import { describe, expect, it, vi } from 'vitest'
import { createAgentPwBetterAuthPlugin } from 'agent.pw/better-auth'
import type { Account } from 'better-auth'

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

describe('Better Auth plugin edge cases', () => {
  it('ignores null and invalid account payloads', async () => {
    const put = vi.fn()
    const plugin = createAgentPwBetterAuthPlugin({
      agentPw: {
        profiles: {
          get: vi.fn(),
        },
        bindings: {
          put,
        },
      } as never,
      selectCredential: vi.fn(() => null),
    })

    const initialized = plugin.init?.({} as never)
    // @ts-expect-error exercising defensive branch from external hook payloads
    await initialized?.options?.databaseHooks?.account?.create?.after?.(null, null)
    // @ts-expect-error exercising runtime guard for invalid update payloads
    await initialized?.options?.databaseHooks?.account?.update?.after?.({ providerId: 'linear' }, null)

    expect(put).not.toHaveBeenCalled()
  })

  it('returns early when account selection does not yield a credential target', async () => {
    const put = vi.fn()
    const plugin = createAgentPwBetterAuthPlugin({
      agentPw: {
        profiles: {
          get: vi.fn(),
        },
        bindings: {
          put,
        },
      } as never,
      selectCredential: vi.fn(() => null),
    })

    const initialized = plugin.init?.({} as never)
    await initialized?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)

    expect(put).not.toHaveBeenCalled()
  })

  it('supports explicit profile paths and custom stored credentials', async () => {
    const put = vi.fn()
    const get = vi.fn(async () => ({
      path: '/org_alpha/linear',
      provider: 'linear',
      host: ['api.linear.app'],
      auth: null,
      oauthConfig: null,
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }))
    const plugin = createAgentPwBetterAuthPlugin({
      agentPw: {
        profiles: { get },
        bindings: { put },
      } as never,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/org_alpha/linear',
          auth: { kind: 'custom' },
        }
      },
      buildStoredCredentials() {
        return {
          headers: { Authorization: 'Bearer custom' },
        }
      },
    })

    const initialized = plugin.init?.({} as never)
    await initialized?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)

    expect(get).toHaveBeenCalledWith('/org_alpha/linear')
    expect(put).toHaveBeenCalledWith({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/org_alpha/linear',
      credentialPath: '/org_alpha/connections/linear_1/linear',
      host: 'api.linear.app',
      auth: { kind: 'custom' },
      secret: {
        headers: { Authorization: 'Bearer custom' },
      },
    })
  })

  it('builds default stored credentials without access tokens or oauth config', async () => {
    const put = vi.fn()
    const get = vi.fn(async () => ({
      path: '/org_alpha/linear',
      provider: 'linear',
      host: ['api.linear.app'],
      auth: null,
      oauthConfig: {
        scopes: 'profile:read',
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    }))

    const plugin = createAgentPwBetterAuthPlugin({
      agentPw: {
        profiles: {
          get,
        },
        bindings: { put },
      } as never,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/org_alpha/linear',
        }
      },
    })

    const initialized = plugin.init?.({} as never)
    await initialized?.options?.databaseHooks?.account?.create?.after?.(makeAccount({
      accessToken: '',
      refreshToken: '',
      accessTokenExpiresAt: null,
      scope: '',
    }), null)

    expect(get).toHaveBeenCalledWith('/org_alpha/linear')
    expect(put).toHaveBeenCalledWith(expect.objectContaining({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/org_alpha/linear',
      credentialPath: '/org_alpha/connections/linear_1/linear',
      host: 'api.linear.app',
      secret: {
        headers: {},
        oauth: {
          accessToken: undefined,
          refreshToken: undefined,
          expiresAt: undefined,
          tokenUrl: undefined,
          clientId: undefined,
          clientSecret: undefined,
          scopes: 'profile:read',
        },
      },
    }))
  })

  it('builds default stored credentials when no profile oauth config exists', async () => {
    const put = vi.fn()
    const get = vi.fn(async () => null)

    const plugin = createAgentPwBetterAuthPlugin({
      agentPw: {
        profiles: {
          get,
        },
        bindings: { put },
      } as never,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/org_alpha/linear',
          host: 'api.linear.app',
        }
      },
    })

    const initialized = plugin.init?.({} as never)
    await initialized?.options?.databaseHooks?.account?.create?.after?.(makeAccount({
      scope: 'repo',
    }), null)

    expect(put).toHaveBeenCalledWith(expect.objectContaining({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/org_alpha/linear',
      secret: expect.objectContaining({
        oauth: expect.objectContaining({
          scopes: 'repo',
        }),
      }),
    }))
  })

  it('rejects invalid targets and missing hosts', async () => {
    const baseAgentPw = {
      profiles: {
        get: vi.fn(),
      },
      bindings: {
        put: vi.fn(),
      },
    } as never

    const invalidPathPlugin = createAgentPwBetterAuthPlugin({
      agentPw: baseAgentPw,
      selectCredential() {
        return {
          root: '/',
          profilePath: '/linear',
        }
      },
    })
    const invalidPathInit = invalidPathPlugin.init?.({} as never)
    await expect(invalidPathInit?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)).rejects.toThrow(
      "Invalid binding root '/'",
    )

    const invalidProfilePlugin = createAgentPwBetterAuthPlugin({
      agentPw: baseAgentPw,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/',
        }
      },
    })
    const invalidProfileInit = invalidProfilePlugin.init?.({} as never)
    await expect(invalidProfileInit?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)).rejects.toThrow(
      "Invalid profile path '/'",
    )

    const missingHostPlugin = createAgentPwBetterAuthPlugin({
      agentPw: baseAgentPw,
      selectCredential() {
        return {
          root: '/org_alpha/connections/linear_1',
          profilePath: '/org_alpha/linear',
        }
      },
    })
    const missingHostInit = missingHostPlugin.init?.({} as never)
    await expect(missingHostInit?.options?.databaseHooks?.account?.create?.after?.(makeAccount(), null)).resolves.toBeUndefined()
    expect(baseAgentPw.bindings.put).toHaveBeenCalledWith(expect.objectContaining({
      host: null,
    }))
  })
})
