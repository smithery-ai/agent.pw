import { AgentPwInputError } from './errors.js'

function escapeRegex(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function normalizeResource(resource: string) {
  let parsed: URL
  try {
    parsed = new URL(resource)
  } catch {
    throw new AgentPwInputError(`Invalid resource '${resource}'`)
  }
  parsed.hash = ''
  return parsed.toString()
}

export function normalizeResourcePattern(pattern: string) {
  const normalized = pattern.trim()
  if (normalized.length === 0) {
    throw new AgentPwInputError('Resource pattern cannot be empty')
  }

  const [prefix] = normalized.split('*')
  if (prefix && !prefix.includes('://')) {
    throw new AgentPwInputError(`Invalid resource pattern '${pattern}'`)
  }

  return normalized
}

export function resourcePatternMatches(pattern: string, resource: string) {
  const normalizedPattern = normalizeResourcePattern(pattern)
  const normalizedResource = normalizeResource(resource)
  const regex = new RegExp(`^${normalizedPattern.split('*').map(escapeRegex).join('.*')}$`)
  return regex.test(normalizedResource)
}

export function anyResourcePatternMatches(patterns: string[], resource: string) {
  return patterns.some(pattern => resourcePatternMatches(pattern, resource))
}
