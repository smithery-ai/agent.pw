import { describe, expect, it } from 'vitest'
import { createAccessService } from 'agent.pw/access'
import { AgentPwInputError } from '../packages/server/src/errors'
import { BISCUIT_PRIVATE_KEY, PUBLIC_KEY_HEX, createTestDb } from './setup'

describe('access service', () => {
  it('mints tokens across owner shapes and inspects invalid tokens', async () => {
    const db = await createTestDb()
    const access = createAccessService({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      publicKeyHex: PUBLIC_KEY_HEX,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    const anonymous = await access.mint({
      rights: [{ action: 'credential.use', root: '/' }],
    })
    const anonymousInspection = await access.inspect(anonymous.token)
    expect(anonymousInspection).toEqual(expect.objectContaining({
      valid: true,
      userId: 'agentpw',
      orgId: null,
      homePath: null,
      scopes: [],
    }))

    const subjectScoped = await access.mint({
      rights: [{ action: 'profile.manage', root: '/org_alpha' }],
      owner: {
        subject: 'service-account',
        scopes: ['repo', 'write'],
      },
    })
    expect(await access.inspect(subjectScoped.token)).toEqual(expect.objectContaining({
      valid: true,
      userId: 'service-account',
      scopes: ['repo', 'write'],
    }))

    expect(await access.inspect('bad-token')).toEqual(expect.objectContaining({
      valid: false,
      revoked: false,
      trackedTokenId: null,
    }))
  })

  it('validates roots and returns authorization failures with facts', async () => {
    const db = await createTestDb()
    const access = createAccessService({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      publicKeyHex: PUBLIC_KEY_HEX,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    const constrained = await access.mint({
      rights: [{ action: 'profile.manage', root: '/org_alpha' }],
      constraints: [{ hosts: 'allowed.host', methods: 'POST', paths: '/org_alpha' }],
      owner: {
        userId: 'user_alpha',
        orgId: 'org_alpha',
        homePath: '/org_alpha',
        scopes: ['repo'],
      },
    })

    await expect(access.authorize({
      token: constrained.token,
      host: 'allowed.host',
      method: 'POST',
      path: 'org_alpha',
      root: '/org_alpha',
      action: 'profile.manage',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(access.authorize({
      token: constrained.token,
      host: 'allowed.host',
      method: 'POST',
      path: '/org_alpha',
      root: 'org_alpha',
      action: 'profile.manage',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    expect(await access.authorize({
      token: 'bad-token',
      host: 'allowed.host',
      method: 'POST',
      path: '/org_alpha/profile',
      root: '/org_alpha',
      action: 'profile.manage',
    })).toEqual({
      authorized: false,
      error: 'Token is invalid',
    })

    expect(await access.authorize({
      token: constrained.token,
      host: 'allowed.host',
      method: 'POST',
      path: '/org_beta/profile',
      root: '/org_beta',
      action: 'profile.manage',
    })).toEqual(expect.objectContaining({
      authorized: false,
      error: "Token is missing 'profile.manage' for '/org_beta/profile'",
      facts: expect.objectContaining({
        userId: 'user_alpha',
        orgId: 'org_alpha',
        homePath: '/org_alpha',
        scopes: ['repo'],
      }),
      trackedTokenId: constrained.id,
    }))

    expect(await access.authorize({
      token: constrained.token,
      host: 'denied.host',
      method: 'POST',
      path: '/org_alpha/profile',
      root: '/org_alpha',
      action: 'profile.manage',
    })).toEqual(expect.objectContaining({
      authorized: false,
      error: expect.any(String),
      trackedTokenId: constrained.id,
    }))
  })

  it('reuses restrictions and reports revoke misses', async () => {
    const db = await createTestDb()
    const access = createAccessService({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      publicKeyHex: PUBLIC_KEY_HEX,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    const minted = await access.mint({
      rights: [{ action: 'credential.use', root: '/org_alpha' }],
      constraints: [{ methods: 'GET', paths: '/org_alpha', ttl: '5m' }],
      owner: { orgId: 'org_alpha' },
    })
    const restricted = access.restrict(minted.token, [{ hosts: 'api.linear.app' }])

    expect(await access.inspect(restricted)).toEqual(expect.objectContaining({
      valid: true,
      orgId: 'org_alpha',
    }))
    expect(await access.revoke(minted.id, 'manual')).toBe(true)
    expect(await access.authorize({
      token: minted.token,
      host: 'api.linear.app',
      method: 'GET',
      path: '/org_alpha/task',
      root: '/org_alpha',
    })).toEqual({
      authorized: false,
      error: 'Token has been revoked',
    })
    expect(await access.revoke('missing-token-id')).toBe(false)
  })
})
