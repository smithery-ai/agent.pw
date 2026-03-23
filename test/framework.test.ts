import { describe, expect, it } from 'vitest'
import { createAgentPw } from 'agent.pw'
import type { StoredCredentials } from '../packages/server/src/lib/credentials-crypto'
import { AgentPwConflictError } from '../packages/server/src/errors'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

function bearerSecret(token: string): StoredCredentials {
  return {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  }
}

describe('createAgentPw', () => {
  it('resolves path-scoped credential profiles and credentials', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    })

    await agentPw.profiles.put('/linear', {
      host: ['api.linear.global'],
      oauthConfig: {
        clientId: 'smithery-client',
      },
    })
    await agentPw.profiles.put('/org_alpha/linear', {
      host: ['api.linear.org'],
    })
    await agentPw.profiles.put('/org_alpha/ws_engineering/linear', {
      host: ['api.linear.engineering'],
    })

    expect(await agentPw.profiles.resolve({
      provider: 'linear',
      root: '/org_alpha/ws_engineering/service',
    })).toEqual(expect.objectContaining({
      path: '/org_alpha/ws_engineering/linear',
      provider: 'linear',
    }))

    expect(await agentPw.profiles.resolve({
      host: 'api.linear.global',
      root: '/org_beta/service',
    })).toEqual(expect.objectContaining({
      path: '/linear',
    }))

    await agentPw.credentials.put('/org_alpha/linear', {
      profilePath: '/linear',
      host: 'api.linear.app',
      auth: { kind: 'headers' },
      secret: bearerSecret('org-token'),
    })
    await agentPw.credentials.put('/org_alpha/ws_engineering/linear', {
      profilePath: '/org_alpha/ws_engineering/linear',
      host: 'api.linear.app',
      auth: { kind: 'headers' },
      secret: bearerSecret('engineering-token'),
    })

    expect(await agentPw.credentials.get('/org_alpha/linear')).toEqual(
      expect.objectContaining({
        path: '/org_alpha/linear',
        profilePath: '/linear',
        secret: { headers: { Authorization: 'Bearer org-token' } },
      }),
    )

    expect(await agentPw.bindings.resolve({
      root: '/org_alpha/ws_engineering/service',
      profilePath: '/org_alpha/ws_engineering/linear',
    })).toEqual(expect.objectContaining({
      path: '/org_alpha/ws_engineering/linear',
      profilePath: '/org_alpha/ws_engineering/linear',
      secret: { headers: { Authorization: 'Bearer engineering-token' } },
    }))

    expect(await agentPw.bindings.resolveHeaders({
      root: '/org_alpha/ws_engineering/service',
      profilePath: '/org_alpha/ws_engineering/linear',
    })).toEqual({
      Authorization: 'Bearer engineering-token',
    })
  })

  it('raises conflicts when same-depth credentials are ambiguous', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    })

    await agentPw.credentials.put('/org_alpha/ws_engineering/linear', {
      profilePath: '/linear',
      host: 'api.linear.app',
      auth: { kind: 'headers' },
      secret: bearerSecret('linear-a'),
    })
    await agentPw.credentials.put('/org_alpha/ws_engineering/linear-shadow', {
      profilePath: '/linear',
      host: 'api.linear.app',
      auth: { kind: 'headers' },
      secret: bearerSecret('linear-b'),
    })

    await expect(agentPw.bindings.resolve({
      root: '/org_alpha/ws_engineering/service',
      profilePath: '/linear',
    })).rejects.toBeInstanceOf(AgentPwConflictError)
  })

  it('mints, authorizes, and revokes tracked access tokens', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    })

    const minted = await agentPw.access.mint({
      rights: [{ action: 'credential.use', root: '/org_alpha' }],
      constraints: [{ hosts: 'api.linear.app', methods: 'GET', paths: '/org_alpha' }],
      owner: {
        userId: 'user_alpha',
        orgId: 'org_alpha',
        homePath: '/org_alpha',
        scopes: ['repo'],
        name: 'Engineering token',
      },
    })

    expect(await agentPw.access.inspect(minted.token)).toEqual(expect.objectContaining({
      valid: true,
      userId: 'user_alpha',
      orgId: 'org_alpha',
      homePath: '/org_alpha',
      trackedTokenId: minted.id,
    }))

    expect(await agentPw.access.authorize({
      token: minted.token,
      host: 'api.linear.app',
      method: 'GET',
      path: '/org_alpha/tasks',
      root: '/org_alpha',
    })).toEqual(expect.objectContaining({
      authorized: true,
      trackedTokenId: minted.id,
    }))

    expect(await agentPw.access.authorize({
      token: minted.token,
      host: 'api.linear.app',
      method: 'GET',
      path: '/org_beta/tasks',
      root: '/org_beta',
    })).toEqual(expect.objectContaining({
      authorized: false,
    }))

    expect(await agentPw.access.revoke(minted.id, 'manual')).toBe(true)
    expect(await agentPw.access.inspect(minted.token)).toEqual(expect.objectContaining({
      valid: false,
      revoked: true,
    }))
  })

  it('stores credentials through explicit bindings', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    })

    await agentPw.profiles.put('/github', {
      host: ['api.github.com'],
    })

    const stored = await agentPw.bindings.put({
      root: '/org_alpha/connections/github_1',
      profilePath: '/github',
      secret: bearerSecret('github-token'),
    })

    expect(stored).toEqual(expect.objectContaining({
      path: '/org_alpha/connections/github_1/github',
      profilePath: '/github',
      host: 'api.github.com',
      profile: expect.objectContaining({
        path: '/github',
      }),
    }))
  })
})
