import { describe, expect, it } from 'vitest'
import { Biscuit, PrivateKey } from '@smithery/biscuit'
import {
  authorizeRequest,
  extractTokenFacts,
  extractUserId,
  generateKeyPairHex,
  getPublicKey,
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

function mintLegacyToken() {
  const builder = Biscuit.builder()
  builder.addCode([
    'user("legacy_user_123");',
    'apw_user_id("legacy_user_123");',
    'right("manage_services");',
    'apw_right("manage_services");',
    `apw_org_id("${TEST_ORG_ID}");`,
    `apw_path("/${TEST_ORG_ID}");`,
  ].join('\n'))
  const token = builder.build(PrivateKey.fromString(BISCUIT_PRIVATE_KEY))
  return `apw_${token.toBase64()}`
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
      `apw:org_id("${TEST_ORG_ID}")`,
      '  ',
      'apw:scope("repo");',
      'apw_scope("write")',
      'custom("value")',
    ])

    const facts = extractTokenFacts(token, PUBLIC_KEY_HEX)
    expect(facts).toEqual({
      rights: ['admin'],
      userId: 'user_test_123',
      orgId: TEST_ORG_ID,
      path: null,
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
      path: null,
      scopes: [],
    })

    const pair = generateKeyPairHex()
    expect(pair.privateKey).toMatch(/^ed25519-private\//)
    expect(pair.publicKey).toMatch(/^ed25519\//)
  })

  it('only extracts namespaced identity facts, ignoring bare legacy facts', () => {
    const bareToken = buildCustomToken([
      'user("legacy-user");',
      'right("admin");',
      'scope("repo");',
    ].join('\n'))

    expect(extractTokenFacts(bareToken, PUBLIC_KEY_HEX)).toEqual({
      rights: [],
      userId: null,
      orgId: null,
      path: null,
      scopes: [],
    })

    const underscoreToken = buildCustomToken([
      'apw_user_id("underscore-user");',
      'apw_org_id("underscore-org");',
      'apw_right("manage_services");',
      'apw_scope("write");',
    ].join('\n'))

    expect(extractTokenFacts(underscoreToken, PUBLIC_KEY_HEX)).toEqual({
      rights: ['manage_services'],
      userId: 'underscore-user',
      orgId: 'underscore-org',
      path: null,
      scopes: ['write'],
    })

    const colonToken = buildCustomToken([
      'apw:user_id("colon-user");',
      'apw:org_id("colon-org");',
      'apw:right("admin");',
      'apw:scope("repo");',
    ].join('\n'))

    expect(extractTokenFacts(colonToken, PUBLIC_KEY_HEX)).toEqual({
      rights: ['admin'],
      userId: 'colon-user',
      orgId: 'colon-org',
      path: null,
      scopes: ['repo'],
    })

    const orgOnlyToken = buildCustomToken('apw:org_id("org-only");')
    expect(extractUserId(orgOnlyToken, PUBLIC_KEY_HEX)).toBe('org-only')
  })

  it('uses only namespaced identity facts and plain ambient request facts', () => {
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'user_test_123', ['manage_services'], [
      `apw:org_id("${TEST_ORG_ID}")`,
      `apw:path("/${TEST_ORG_ID}")`,
    ])
    const publicKey = getPublicKey(BISCUIT_PRIVATE_KEY)
    const biscuit = Biscuit.fromBase64(stripPrefix(token), publicKey)
    const authority = biscuit.getBlockSource(0)
    const authorityLines = authority.split('\n').map(line => line.trim()).filter(Boolean)

    expect(authorityLines).toContain('apw:user_id("user_test_123");')
    expect(authorityLines).toContain('apw:right("manage_services");')
    expect(authorityLines).not.toContain('user("user_test_123");')
    expect(authorityLines).not.toContain('right("manage_services");')

    const restricted = restrictToken(token, PUBLIC_KEY_HEX, [
      { services: 'github', methods: 'GET', paths: '/user' },
    ])
    const attenuated = Biscuit.fromBase64(stripPrefix(restricted), publicKey)
    const block = attenuated.getBlockSource(1)

    expect(block).toContain('resource($r)')
    expect(block).toContain('operation($op)')
    expect(block).toContain('path($p)')
    expect(block).not.toContain('apw:resource')
    expect(block).not.toContain('apw:operation')
    expect(block).not.toContain('apw:path')
  })

  it('accepts legacy underscore facts for internal compatibility', () => {
    const legacyToken = mintLegacyToken()

    expect(authorizeRequest(legacyToken, PUBLIC_KEY_HEX, '_management', 'PUT', '/cred_profiles/linear').authorized).toBe(true)

    const facts = extractTokenFacts(legacyToken, PUBLIC_KEY_HEX)
    expect(facts.userId).toBe('legacy_user_123')
    expect(facts.orgId).toBe(TEST_ORG_ID)
    expect(facts.path).toBe(`/${TEST_ORG_ID}`)
    expect(facts.rights).toContain('manage_services')
  })
})
