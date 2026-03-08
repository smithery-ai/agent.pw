export type SelectorRecord = Record<string, string>

function comparePairs(a: string, b: string) {
  return a.localeCompare(b)
}

function escapeDatalog(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export function parseSelectorRecord(value: unknown): SelectorRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null

  const result: SelectorRecord = {}
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry !== 'string') return null
    result[key] = entry
  }

  return result
}

export function selectorPairs(selectors: SelectorRecord | null | undefined): string[] {
  if (!selectors) return []
  return Object.entries(selectors)
    .map(([key, value]) => `${key}=${value}`)
    .sort(comparePairs)
}

export function selectorsMatch(
  required: SelectorRecord | null | undefined,
  actual: SelectorRecord | null | undefined,
): boolean {
  const expected = required ?? {}
  const available = actual ?? {}

  return Object.entries(expected).every(([key, value]) => available[key] === value)
}

export function selectorFacts(selectors: SelectorRecord, predicate = 'selector'): string[] {
  return Object.entries(selectors)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${predicate}("${escapeDatalog(key)}", "${escapeDatalog(value)}")`)
}

export function selectorsFromTokenFacts(facts: {
  selectors?: SelectorRecord
  orgId?: string | null
  userId?: string | null
}): SelectorRecord {
  if (facts.selectors && Object.keys(facts.selectors).length > 0) {
    return facts.selectors
  }

  if (facts.orgId) {
    return { org: facts.orgId }
  }

  if (facts.userId) {
    return { user: facts.userId }
  }

  return {}
}
