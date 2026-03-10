import { describe, expect, it } from 'vitest'
import { Biscuit, PrivateKey } from '@smithery/biscuit'
import {
  authorizeRequest,
  extractTokenFacts,
  extractUserId,
  generateKeyPairHex,
  getPublicKeyHex,
  getRevocationIds,
  mintToken,
  parseTtlSeconds,
  restrictToken,
  stripPrefix,
} from '@agent.pw/server/biscuit'
import { BISCUIT_PRIVATE_KEY, ORG_TOKEN, PUBLIC_KEY_HEX, TEST_ORG_ID } from './setup'

function buildCustomToken(code: string) {
  const builder = Biscuit.builder()
  builder.addCode(code)
  return builder.build(PrivateKey.fromString(BISCUIT_PRIVATE_KEY)).toBase64()
}

describe('biscuit helpers', () => {
  it('strips prefixes and parses TTL values', () => {
    expect(stripPrefix('apw_abc')).toBe('abc')
    expect(stripPrefix('plain')).toBe('plain')
    expect(parseTtlSeconds(60)).toBe(60)
    expect(parseTtlSeconds('30')).toBe(30)
    expect(parseTtlSeconds('5s')).toBe(5)
    expect(parseTtlSeconds('5m')).toBe(300)
    expect(parseTtlSeconds('2h')).toBe(7200)
    expect(parseTtlSeconds('1d')).toBe(86400)
    expect(() => parseTtlSeconds('soon')).toThrow('Invalid TTL format: soon')
  })

  it('mints tokens, extracts facts, and derives public metadata', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'user_test_123', ['admin'], [
      `org_id("${TEST_ORG_ID}")`,
      '  ',
      'scope("repo");',
      'apw_scope("write")',
      'custom("value")',
    ])

    const facts = extractTokenFacts(token, PUBLIC_KEY_HEX)
    expect(facts).toEqual({
      rights: ['admin'],
      userId: 'user_test_123',
      orgId: TEST_ORG_ID,
      scopes: ['repo', 'write'],
    })
    expect(extractUserId(token, PUBLIC_KEY_HEX)).toBe('user_test_123')
    expect(getPublicKeyHex(BISCUIT_PRIVATE_KEY)).toBe(PUBLIC_KEY_HEX)
    expect(getRevocationIds(token, PUBLIC_KEY_HEX).length).toBeGreaterThan(0)
  })

  it('restricts tokens against service, method, path, and TTL constraints', () => {
    const unrestricted = restrictToken(ORG_TOKEN, PUBLIC_KEY_HEX, [])
    expect(unrestricted).toBe(ORG_TOKEN)

    const restricted = restrictToken(ORG_TOKEN, PUBLIC_KEY_HEX, [
      { services: ['github', 'gitlab'], methods: ['GET', 'POST'], paths: ['/user', '/repos'], ttl: '5m' },
      { services: 'linear', methods: 'HEAD', paths: '/graphql', ttl: 600 },
    ])

    expect(restricted).not.toBe(ORG_TOKEN)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'github', 'GET', '/user').authorized).toBe(true)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'gitlab', 'POST', '/repos/1').authorized).toBe(true)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'linear', 'HEAD', '/graphql').authorized).toBe(true)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'github', 'DELETE', '/user').authorized).toBe(false)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'github', 'GET', '/admin').authorized).toBe(false)
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, 'other', 'GET', '/user').authorized).toBe(false)
    expect(authorizeRequest('bad-token', PUBLIC_KEY_HEX, 'github', 'GET', '/user')).toEqual({
      authorized: false,
      error: expect.any(String),
    })
  })

  it('returns empty facts for invalid tokens and generates key pairs', () => {
    expect(extractTokenFacts('bad-token', PUBLIC_KEY_HEX)).toEqual({
      rights: [],
      userId: null,
      orgId: null,
      scopes: [],
    })

    const pair = generateKeyPairHex()
    expect(pair.privateKey).toMatch(/^ed25519-private\//)
    expect(pair.publicKey).toMatch(/^ed25519\//)
  })

  it('extracts legacy and managed identity facts from custom authority blocks', () => {
    const legacyToken = buildCustomToken([
      'user("legacy-user");',
      'right("admin");',
      'scope("repo");',
    ].join('\n'))

    expect(extractTokenFacts(legacyToken, PUBLIC_KEY_HEX)).toEqual({
      rights: ['admin'],
      userId: 'legacy-user',
      orgId: null,
      scopes: ['repo'],
    })

    const managedToken = buildCustomToken([
      'user_id("managed-user");',
      'org_id("managed-org");',
      'apw_scope("write");',
    ].join('\n'))

    expect(extractTokenFacts(managedToken, PUBLIC_KEY_HEX)).toEqual({
      rights: [],
      userId: 'managed-user',
      orgId: 'managed-org',
      scopes: ['write'],
    })

    const orgOnlyToken = buildCustomToken('org_id("org-only");')
    expect(extractUserId(orgOnlyToken, PUBLIC_KEY_HEX)).toBe('org-only')
  })
})
