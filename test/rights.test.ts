import { describe, expect, it } from 'vitest'
import {
  authorizeRules,
  can,
  constraintAppliesToPath,
  coveringRootsForPath,
  hasActionRight,
  hasRuleForPath,
  normalizeConstraintValues,
  rootsForAction,
  rootsForActionFromScope,
  rootsForActions,
  uniqueRoots,
} from 'agent.pw/rules'

describe('rules helpers', () => {
  const rights = [
    { action: 'credential.use', root: '/org_alpha' },
    { action: 'credential.use', root: '/org_alpha/team' },
    { action: 'credential.manage', root: '/org_alpha' },
    { action: 'credential.use', root: '/org_alpha' },
  ]

  it('deduplicates and sorts deeper roots first', () => {
    expect(uniqueRoots(['/org_alpha', '/org_alpha/team', '/org_alpha'])).toEqual([
      '/org_alpha/team',
      '/org_alpha',
    ])
  })

  it('sorts same-depth roots lexicographically', () => {
    expect(uniqueRoots(['/org_beta', '/org_alpha'])).toEqual([
      '/org_alpha',
      '/org_beta',
    ])
  })

  it('filters roots by one or many actions', () => {
    expect(rootsForAction(rights, 'credential.use')).toEqual([
      '/org_alpha/team',
      '/org_alpha',
    ])
    expect(rootsForActions(rights, ['credential.use', 'credential.manage'])).toEqual([
      '/org_alpha/team',
      '/org_alpha',
    ])
  })

  it('checks action presence and root coverage from facts', () => {
    expect(hasActionRight(rights, 'credential.manage')).toBe(true)
    expect(hasActionRight(rights, 'profile.manage')).toBe(false)
    expect(hasRuleForPath(rights, 'credential.use', '/org_alpha/team/tool')).toBe(true)
    expect(coveringRootsForPath(['/org_alpha', '/org_alpha/team'], '/org_alpha/team/tool')).toEqual([
      '/org_alpha/team',
      '/org_alpha',
    ])
    expect(rootsForActionFromScope({ rights }, 'credential.manage')).toEqual(['/org_alpha'])
  })

  it('authorizes rules and evaluates request constraints', () => {
    expect(authorizeRules({
      rights,
      action: 'credential.use',
      path: '/org_alpha/team/tool',
    })).toEqual({ authorized: true })

    expect(authorizeRules({
      rights,
      action: 'profile.manage',
      path: '/org_alpha/team/tool',
    })).toEqual({
      authorized: false,
      error: "Missing 'profile.manage' for '/org_alpha/team/tool'",
    })

    expect(constraintAppliesToPath({
      actions: 'credential.use',
      hosts: 'api.linear.app',
      methods: 'GET',
      roots: '/org_alpha',
      paths: '/org_alpha/team',
      services: 'linear',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'get',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
      service: 'linear',
    })).toBe(true)

    expect(constraintAppliesToPath({
      hosts: 'api.linear.app',
    }, {
      action: 'credential.use',
      host: 'api.github.com',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(constraintAppliesToPath({
      actions: 'profile.manage',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(constraintAppliesToPath({
      methods: 'POST',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(constraintAppliesToPath({
      roots: '/org_beta',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(constraintAppliesToPath({
      services: 'linear',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(constraintAppliesToPath({
      paths: '/org_beta',
    }, {
      action: 'credential.use',
      host: 'api.linear.app',
      method: 'GET',
      root: '/org_alpha',
      path: '/org_alpha/team/tool',
    })).toBe(false)

    expect(normalizeConstraintValues(undefined)).toEqual([])
    expect(normalizeConstraintValues('credential.use')).toEqual(['credential.use'])
    expect(normalizeConstraintValues(['credential.use', 'credential.manage'])).toEqual([
      'credential.use',
      'credential.manage',
    ])

    expect(can({
      rights,
      action: 'credential.use',
      path: '/org_alpha/team/tool',
    })).toBe(true)
    expect(can({
      rights,
      action: 'profile.manage',
      path: '/org_alpha/team/tool',
    })).toBe(false)
  })
})
