import type { TokenFacts, TokenRight } from './core/types'
import { isAncestorOrEqual, pathDepth } from './paths'

function compareRoots(a: string, b: string) {
  return pathDepth(b) - pathDepth(a) || a.localeCompare(b)
}

export function uniqueRoots(roots: string[]) {
  return [...new Set(roots)].sort(compareRoots)
}

export function rootsForAction(rights: TokenRight[], action: string) {
  return uniqueRoots(
    rights
      .filter(right => right.action === action)
      .map(right => right.root),
  )
}

export function rootsForActions(rights: TokenRight[], actions: string[]) {
  return uniqueRoots(
    rights
      .filter(right => actions.includes(right.action))
      .map(right => right.root),
  )
}

export function hasActionRight(rights: TokenRight[], action: string) {
  return rights.some(right => right.action === action)
}

export function coveringRootsForPath(roots: string[], path: string) {
  return roots.filter(root => isAncestorOrEqual(root, path)).sort(compareRoots)
}

export function hasRightForPath(rights: TokenRight[], action: string, path: string) {
  return coveringRootsForPath(rootsForAction(rights, action), path).length > 0
}

export function rootsForActionFromFacts(facts: TokenFacts, action: string) {
  return rootsForAction(facts.rights, action)
}
