import { describe, expect, it } from 'vitest'
import {
  authorizeRequest,
  extractTokenFacts,
  parseTtlSeconds,
  restrictToken,
  stripPrefix,
} from '../src/biscuit'
import { ORG_TOKEN, PUBLIC_KEY_HEX, TEST_ORG_ID } from './setup'

describe('Biscuit Helpers', () => {
  it('handles prefixing, ttl parsing, attenuation, and org facts', () => {
    expect(stripPrefix('apw_abc')).toBe('abc')
    expect(parseTtlSeconds('5m')).toBe(300)

    const restricted = restrictToken(ORG_TOKEN, PUBLIC_KEY_HEX, [
      { services: 'github', methods: 'GET' },
    ])

    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'github', 'GET', '/user').authorized).toBe(true)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'github', 'POST', '/user').authorized).toBe(false)

    const facts = extractTokenFacts(ORG_TOKEN, PUBLIC_KEY_HEX)
    expect(facts.userId).toBe('user_test_123')
    expect(facts.orgId).toBe(TEST_ORG_ID)
  })
})
