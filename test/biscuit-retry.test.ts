import { describe, expect, it, vi } from 'vitest'
import { BISCUIT_PRIVATE_KEY, PUBLIC_KEY_HEX } from './setup'

const state = vi.hoisted(() => ({
  attempts: 0,
  mode: 'retry-once' as 'retry-once' | 'always-timeout' | 'string-failure',
}))

vi.mock('@smithery/biscuit', async importOriginal => {
  const actual = await importOriginal<typeof import('@smithery/biscuit')>()

  class FakeAuthorizerBuilder extends actual.AuthorizerBuilder {
    buildAuthenticated() {
      state.attempts += 1
      if (state.mode === 'string-failure') {
        return {
          authorizeWithLimits() {
            throw 'policy failed'
          },
        } as any
      }

      if (state.mode === 'always-timeout' || state.attempts === 1) {
        return {
          authorizeWithLimits() {
            throw new Error('Timeout while warming up')
          },
        } as any
      }
      return {
        authorizeWithLimits() {
          return undefined
        },
      } as any
    }
  }

  return {
    ...actual,
    AuthorizerBuilder: FakeAuthorizerBuilder,
  }
})

import { authorizeRequest, mintToken } from '../packages/server/src/biscuit'

describe('biscuit authorization retries', () => {
  it('retries timeout warmups once before succeeding', () => {
    state.attempts = 0
    state.mode = 'retry-once'

    const adminToken = mintToken(BISCUIT_PRIVATE_KEY, 'retry-user', [
      { action: 'credential.use', root: '/' },
    ])
    expect(authorizeRequest(adminToken, PUBLIC_KEY_HEX, 'github', 'GET', '/user')).toEqual({
      authorized: true,
    })
    expect(state.attempts).toBe(2)

    state.attempts = 0
    state.mode = 'always-timeout'
    expect(authorizeRequest(adminToken, PUBLIC_KEY_HEX, 'github', 'GET', '/user')).toEqual({
      authorized: false,
      error: 'Timeout while warming up',
    })
    expect(state.attempts).toBe(2)

    state.attempts = 0
    state.mode = 'string-failure'
    expect(authorizeRequest(adminToken, PUBLIC_KEY_HEX, 'github', 'GET', '/user')).toEqual({
      authorized: false,
      error: 'policy failed',
    })
    expect(state.attempts).toBe(1)
  })
})
