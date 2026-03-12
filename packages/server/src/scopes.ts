function compareStrings(a: string, b: string) {
  return a.localeCompare(b)
}

function escapeDatalog(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export function parseScopes(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null
  if (!value.every(scope => typeof scope === 'string')) return null
  return [...value]
}

export function scopesMatch(
  credScopes: string[] | null | undefined,
  tokenScopes: string[] | null | undefined,
): boolean {
  const required = credScopes ?? []
  const available = new Set(tokenScopes ?? [])
  return required.every(scope => available.has(scope))
}

export function scopeFacts(scopes: string[], predicate = 'scope'): string[] {
  return [...scopes]
    .sort(compareStrings)
    .map(scope => `${predicate}("${escapeDatalog(scope)}")`)
}

export function scopesFromTokenFacts(facts: {
  scopes?: string[]
  orgId?: string | null
}): string[] {
  if (facts.scopes && facts.scopes.length > 0) {
    return facts.scopes
  }

  if (facts.orgId) {
    return [`org_id:${facts.orgId}`]
  }

  return []
}
