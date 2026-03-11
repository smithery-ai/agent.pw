import { describe, expect, it } from 'vitest'
import {
  coveringRootsForPath,
  hasActionRight,
  rootsForAction,
  rootsForActionFromFacts,
  rootsForActions,
  uniqueRoots,
} from '../packages/server/src/rights'

describe('rights helpers', () => {
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

  it('sorts same-depth roots lexically after depth', () => {
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
    expect(coveringRootsForPath(['/org_alpha', '/org_alpha/team'], '/org_alpha/team/tool')).toEqual([
      '/org_alpha/team',
      '/org_alpha',
    ])
    expect(rootsForActionFromFacts({ rights }, 'credential.manage')).toEqual(['/org_alpha'])
  })
})
