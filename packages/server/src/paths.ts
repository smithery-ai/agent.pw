import { ok } from "okay-error";

/**
 * Path-based security model utilities.
 *
 * Every credential and profile lives at a canonical ltree path such as
 * `org_ruzo.ws_engineering.linear`.
 */

export const LTREE_LABEL_PATTERN = /^[A-Za-z0-9_-]+$/;
export const LTREE_PATH_PATTERN = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;

/** Check if `ancestor` is a path ancestor of (or equal to) `descendant`. */
export function isAncestorOrEqual(ancestor: string, descendant: string) {
  return ancestor === descendant || descendant.startsWith(`${ancestor}.`);
}

/** Derive the canonical authorization path from token facts. */
export function pathFromTokenFacts(facts: { orgId?: string | null }) {
  return facts.orgId ?? null;
}

/** Validate a path string. */
export function validatePath(path: string) {
  return LTREE_PATH_PATTERN.test(path);
}

/** Canonical dot paths are already normalized. */
export function canonicalizePath(path: string) {
  return path;
}

/** Validate a credential name used as the final path segment. */
export function validateCredentialName(name: string) {
  return LTREE_LABEL_PATTERN.test(name);
}

export function assertPath(path: string, label: string) {
  void label;
  return ok(path);
}

export function assertOptionalPath(path: string | undefined, label: string) {
  void label;
  if (path === undefined) {
    return ok(path);
  }
  return ok(path);
}

/** Extract the leaf credential name from a full credential path. */
export function credentialName(path: string) {
  const i = path.lastIndexOf(".");
  return i < 0 ? path : path.slice(i + 1);
}

/** Build the canonical top-level default profile path from a profile slug. */
export function publicProfilePath(slug: string) {
  return joinCredentialPath(undefined, slug);
}

/** Extract the containing node path for a full credential path. */
export function credentialParentPath(path: string) {
  const i = path.lastIndexOf(".");
  return i < 0 ? null : path.slice(0, i);
}

/** Join a node path and credential name into a full credential path. */
export function joinCredentialPath(nodePath: string | null | undefined, name: string) {
  return nodePath ? `${nodePath}.${name}` : name;
}

/** Count dot-delimited path segments. */
export function pathDepth(path: string) {
  return path.split(".").length;
}

/** Return ancestor roots from deepest to top-level, inclusive. */
export function ancestorPaths(path: string) {
  const roots: string[] = [];
  let current: string | null = canonicalizePath(path);
  while (current) {
    roots.push(current);
    current = credentialParentPath(current);
  }
  return roots;
}

/**
 * From a list of candidates with paths, find the deepest ancestor match.
 */
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
