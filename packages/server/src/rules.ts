import { isAncestorOrEqual, pathDepth } from './paths.js'
import { AgentPwAuthorizationError } from './errors.js'
import type {
  RuleAuthorizationInput,
  RuleAuthorizationResult,
  RuleConstraint,
  RuleFacts,
  RuleGrant,
} from './types.js'

function compareRoots(a: string, b: string) {
  return pathDepth(b) - pathDepth(a) || a.localeCompare(b)
}

export function uniqueRoots(roots: string[]) {
  return [...new Set(roots)].sort(compareRoots)
}

export function rootsForAction(rights: RuleGrant[], action: string) {
  return uniqueRoots(
    rights
      .filter(right => right.action === action)
      .map(right => right.root),
  )
}

export function rootsForActions(rights: RuleGrant[], actions: string[]) {
  return uniqueRoots(
    rights
      .filter(right => actions.includes(right.action))
      .map(right => right.root),
  )
}

export function hasActionRight(rights: RuleGrant[], action: string) {
  return rights.some(right => right.action === action)
}

export function coveringRootsForPath(roots: string[], path: string) {
  return roots.filter(root => isAncestorOrEqual(root, path)).sort(compareRoots)
}

export function hasRuleForPath(rights: RuleGrant[], action: string, path: string) {
  return coveringRootsForPath(rootsForAction(rights, action), path).length > 0
}

export function rootsForActionFromFacts(facts: RuleFacts, action: string) {
  return rootsForAction(facts.rights, action)
}

export function authorizeRules(input: RuleAuthorizationInput): RuleAuthorizationResult {
  if (!hasRuleForPath(input.rights, input.action, input.path)) {
    return {
      authorized: false,
      error: `Missing '${input.action}' for '${input.path}'`,
    }
  }

  return { authorized: true }
}

export function can(input: RuleAuthorizationInput) {
  return authorizeRules(input).authorized
}

export function assertCan(input: RuleAuthorizationInput) {
  const result = authorizeRules(input)
  if (!result.authorized) {
    throw new AgentPwAuthorizationError(input.action, input.path, result.error)
  }
}

export function normalizeConstraintValues(value: string | string[] | undefined) {
  if (value === undefined) {
    return []
  }
  return Array.isArray(value) ? value : [value]
}

export function constraintAppliesToPath(
  constraint: RuleConstraint,
  input: {
    action: string
    host: string
    method: string
    path: string
    root: string
    service?: string
  },
) {
  const actions = normalizeConstraintValues(constraint.actions)
  if (actions.length > 0 && !actions.includes(input.action)) {
    return false
  }

  const hosts = normalizeConstraintValues(constraint.hosts)
  if (hosts.length > 0 && !hosts.includes(input.host)) {
    return false
  }

  const methods = normalizeConstraintValues(constraint.methods)
  if (methods.length > 0 && !methods.includes(input.method.toUpperCase())) {
    return false
  }

  const roots = normalizeConstraintValues(constraint.roots)
  if (roots.length > 0 && !roots.includes(input.root)) {
    return false
  }

  const services = normalizeConstraintValues(constraint.services)
  if (services.length > 0 && !(input.service && services.includes(input.service))) {
    return false
  }

  const paths = normalizeConstraintValues(constraint.paths)
  if (paths.length > 0 && !paths.some(path => input.path.startsWith(path))) {
    return false
  }

  return true
}
