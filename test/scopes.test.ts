import { describe, expect, it } from 'vitest'
import {
  parseScopes,
  scopeFacts,
  scopesFromTokenFacts,
  scopesMatch,
} from '@agent.pw/server/scopes'

describe('scopes helpers', () => {
  it('parses scope arrays and rejects invalid values', () => {
    const scopes = ['repo', 'read:user']
    expect(parseScopes(scopes)).toEqual(scopes)
    expect(parseScopes('repo')).toBeNull()
    expect(parseScopes(['repo', 123])).toBeNull()
  })

  it('matches required scopes against token scopes', () => {
    expect(scopesMatch(['repo'], ['repo', 'read:user'])).toBe(true)
    expect(scopesMatch(['repo', 'admin'], ['repo'])).toBe(false)
    expect(scopesMatch(null, undefined)).toBe(true)
  })

  it('builds escaped, sorted datalog scope facts', () => {
    expect(scopeFacts(['zeta', 'a"b', 'c\\d'], 'apw_scope')).toEqual([
      'apw_scope("a\\"b")',
      'apw_scope("c\\\\d")',
      'apw_scope("zeta")',
    ])
  })

  it('reads scopes from token facts with org fallback', () => {
    expect(scopesFromTokenFacts({ scopes: ['repo'] })).toEqual(['repo'])
    expect(scopesFromTokenFacts({ orgId: 'org_test' })).toEqual(['org_id:org_test'])
    expect(scopesFromTokenFacts({})).toEqual([])
  })
})
