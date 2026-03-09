/**
 * Path-based security model utilities.
 *
 * Every credential and profile lives at a canonical path in a tree that
 * encodes organizational hierarchy (e.g. /orgs/ruzo/ws/engineering).
 *
 * Two directions of access:
 * - Usage flows upward: credentials at ancestor paths are inherited
 * - Admin flows downward: tokens manage objects at their path or deeper
 */

/** Check if `ancestor` is a path ancestor of (or equal to) `descendant`. */
export function isAncestorOrEqual(ancestor: string, descendant: string) {
  if (ancestor === descendant) return true
  if (ancestor === '/') return true
  // Ensure boundary match: /orgs/ab must NOT match /orgs/abc
  const prefix = ancestor.endsWith('/') ? ancestor : ancestor + '/'
  return descendant.startsWith(prefix)
}

/** Derive the canonical path from token facts (orgId → /orgs/{orgId}). */
export function pathFromTokenFacts(facts: { orgId?: string | null }) {
  if (facts.orgId) return `/orgs/${facts.orgId}`
  return '/'
}

/** Validate a path string. */
export function validatePath(path: string) {
  if (!path.startsWith('/')) return false
  if (path !== '/' && path.endsWith('/')) return false
  if (path.includes('..')) return false
  return true
}

/**
 * From a list of candidates with paths, find the deepest ancestor of
 * `tokenPath` (longest prefix match). Returns null if none match.
 */
export function deepestAncestor<T extends { path: string }>(
  candidates: T[],
  tokenPath: string,
): T | null {
  let best: T | null = null
  for (const c of candidates) {
    if (!isAncestorOrEqual(c.path, tokenPath)) continue
    if (!best || c.path.length > best.path.length) best = c
  }
  return best
}

/** Escape special LIKE characters in a path for use in SQL LIKE patterns. */
export function escapeLikePath(path: string) {
  return path.replace(/%/g, '\\%').replace(/_/g, '\\_')
}
