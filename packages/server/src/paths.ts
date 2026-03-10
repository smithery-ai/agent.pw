/**
 * Path-based security model utilities.
 *
 * Every credential and profile lives at a canonical path in a tree that
 * encodes organizational hierarchy (e.g. /org_ruzo/ws/engineering).
 *
 * Two directions of access:
 * - Usage flows upward: credentials at ancestor paths are inherited
 * - Admin flows downward: tokens manage objects at their path or deeper
 */

/** Check if `ancestor` is a path ancestor of (or equal to) `descendant`. */
export function isAncestorOrEqual(ancestor: string, descendant: string) {
  if (ancestor === descendant) return true
  if (ancestor === '/') return true
  // Ensure boundary match: /ab must NOT match /abc
  const prefix = ancestor.endsWith('/') ? ancestor : ancestor + '/'
  return descendant.startsWith(prefix)
}

/** Derive the canonical authorization path from token facts (orgId → /{orgId}). */
export function pathFromTokenFacts(facts: { orgId?: string | null }) {
  if (facts.orgId) return `/${facts.orgId}`
  return '/'
}

/** Validate a path string. */
export function validatePath(path: string) {
  if (!path.startsWith('/')) return false
  if (path !== '/' && path.endsWith('/')) return false
  if (path.includes('..')) return false
  return true
}

/** Extract the leaf credential name from a full credential path. */
export function credentialName(path: string) {
  return path.split('/').pop()!
}

/** Extract the containing node path for a full credential path. */
export function credentialParentPath(path: string) {
  const i = path.lastIndexOf('/')
  return i <= 0 ? '/' : path.slice(0, i)
}

/** Join a node path and credential name into a full credential path. */
export function joinCredentialPath(nodePath: string, name: string) {
  return nodePath === '/' ? `/${name}` : `${nodePath}/${name}`
}

/** Validate a credential name used as the final path segment. */
export function validateCredentialName(name: string) {
  return name.length > 0 && !name.includes('/') && !name.includes('.') && name !== '.' && name !== '..'
}

/** Count slash-delimited path segments, excluding the leading slash. */
export function pathDepth(path: string) {
  if (path === '/') return 0
  return path.split('/').filter(Boolean).length
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
