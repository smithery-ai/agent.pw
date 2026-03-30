import { ok } from "okay-error";

/**
 * Path-based security model utilities.
 *
 * Every credential and profile lives at a canonical ltree path such as
 * `org_ruzo.ws_engineering.linear`.
 */

/** Regular expression for one canonical agent.pw path segment. */
export const LTREE_LABEL_PATTERN = /^[A-Za-z0-9_-]+$/;
/** Regular expression for a full dot-delimited canonical agent.pw path. */
export const LTREE_PATH_PATTERN = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;

/** Return `true` when `ancestor` covers `descendant`, including an exact match. */
export function isAncestorOrEqual(ancestor: string, descendant: string) {
  return ancestor === descendant || descendant.startsWith(`${ancestor}.`);
}

/** Extract the authorization root encoded in token facts. */
export function pathFromTokenFacts(facts: { orgId?: string | null }) {
  return facts.orgId ?? null;
}

/** Return `true` when `path` matches the canonical agent.pw ltree syntax. */
export function validatePath(path: string) {
  return LTREE_PATH_PATTERN.test(path);
}

/** Return the canonical path representation. Current paths are already normalized. */
export function canonicalizePath(path: string) {
  return path;
}

/** Return `true` when `name` is valid as the final segment of a credential path. */
export function validateCredentialName(name: string) {
  return LTREE_LABEL_PATTERN.test(name);
}

/**
 * Wrap a required path in a `Result` so higher-level APIs can keep a consistent `okay-error`
 * contract. The current implementation preserves the original string.
 */
export function assertPath(path: string, label: string) {
  void label;
  return ok(path);
}

/**
 * Wrap an optional path in a `Result` for APIs that accept absent path filters. The current
 * implementation preserves the original string when present.
 */
export function assertOptionalPath(path: string | undefined, label: string) {
  void label;
  if (path === undefined) {
    return ok(path);
  }
  return ok(path);
}

/** Return the leaf credential name from a full credential path. */
export function credentialName(path: string) {
  const i = path.lastIndexOf(".");
  return i < 0 ? path : path.slice(i + 1);
}

/** Build the canonical top-level profile path for a public profile slug. */
export function publicProfilePath(slug: string) {
  return joinCredentialPath(undefined, slug);
}

/** Return the containing node path for a full credential path. */
export function credentialParentPath(path: string) {
  const i = path.lastIndexOf(".");
  return i < 0 ? null : path.slice(0, i);
}

/** Join a node path and credential name into a canonical full credential path. */
export function joinCredentialPath(nodePath: string | null | undefined, name: string) {
  return nodePath ? `${nodePath}.${name}` : name;
}

/** Count the number of dot-delimited path segments. */
export function pathDepth(path: string) {
  return path.split(".").length;
}

/** Return `path` and each ancestor root, ordered deepest-first. */
export function ancestorPaths(path: string) {
  const roots: string[] = [];
  let current: string | null = canonicalizePath(path);
  while (current) {
    roots.push(current);
    current = credentialParentPath(current);
  }
  return roots;
}

/** Pick the deepest candidate whose `path` covers `tokenPath`. */
export function deepestAncestor<T extends { path: string }>(
  candidates: T[],
  tokenPath: string,
): T | null {
  let best: T | null = null;
  for (const c of candidates) {
    if (!isAncestorOrEqual(c.path, tokenPath)) continue;
    if (!best || pathDepth(c.path) > pathDepth(best.path)) best = c;
  }
  return best;
}
