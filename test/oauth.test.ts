import { describe, expect, it } from 'vitest'
import { AgentPwInputError } from '../packages/server/src/errors'
import { createInMemoryFlowStore, createOAuthService } from 'agent.pw/oauth'

describe('oauth flow service', () => {
  it('creates, reads, completes, and deletes pending flows', async () => {
    const flowStore = createInMemoryFlowStore()
    const oauth = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    const flow = await oauth.start({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/linear',
    })

    expect(flow.id).toHaveLength(96)
    expect(flow.codeVerifier).toHaveLength(96)
    expect(flow.expiresAt.toISOString()).toBe('2026-01-01T00:10:00.000Z')
    expect(await oauth.get(flow.id)).toEqual(flow)

    await oauth.complete(flow.id, { identity: 'acct_123' })
    expect(await oauth.get(flow.id)).toEqual(expect.objectContaining({
      identity: 'acct_123',
    }))

    await oauth.delete(flow.id)
    expect(await oauth.get(flow.id)).toBeNull()
  })

  it('accepts explicit ids and ignores missing flow completion', async () => {
    const oauth = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    const flow = await oauth.start({
      id: 'x'.repeat(32),
      root: '/org_alpha/connections/github_1',
      profilePath: '/github',
      codeVerifier: 'verifier',
      expiresAt: new Date('2026-02-01T00:00:00.000Z'),
    })

    expect(flow).toEqual(expect.objectContaining({
      id: 'x'.repeat(32),
      codeVerifier: 'verifier',
      expiresAt: new Date('2026-02-01T00:00:00.000Z'),
    }))

    await expect(oauth.complete('missing')).resolves.toBeUndefined()
    await expect(oauth.delete('missing')).resolves.toBeUndefined()
  })

  it('validates flow roots and profile paths', async () => {
    const oauth = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    await expect(oauth.start({
      root: '/',
      profilePath: '/linear',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(oauth.start({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/',
    })).rejects.toBeInstanceOf(AgentPwInputError)
  })
})
