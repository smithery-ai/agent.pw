import { describe, expect, it } from 'vitest'
import { createAgentPw } from 'agent.pw'
import type { StoredCredentials } from '../packages/server/src/lib/credentials-crypto'
import { deriveEncryptionKey } from '../packages/server/src/lib/credentials-crypto'
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
    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const agentPw = await createAgentPw({
      db,
      encryptionKey,
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

  it('returns null when an explicit credential path belongs to another profile', async () => {
    const db = await createTestDb()
    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const agentPw = await createAgentPw({
      db,
      encryptionKey,
    })

    await agentPw.credentials.put('/org_alpha/ws_engineering/team_a/linear', {
      profilePath: '/linear',
      host: 'api.linear.app',
      auth: { kind: 'headers' },
      secret: bearerSecret('linear-a'),
    })
    await agentPw.credentials.put('/org_alpha/ws_engineering/team_a/github', {
      profilePath: '/github',
      host: 'api.github.com',
      auth: { kind: 'headers' },
      secret: bearerSecret('github-a'),
    })

    await expect(agentPw.bindings.resolve({
      root: '/org_alpha/ws_engineering/team_a',
      profilePath: '/linear',
      credentialPath: '/org_alpha/ws_engineering/team_a/github',
      refresh: false,
    })).resolves.toBeNull()
  })

  it('stores credentials through explicit bindings', async () => {
    const db = await createTestDb()
    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const agentPw = await createAgentPw({
      db,
      encryptionKey,
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
