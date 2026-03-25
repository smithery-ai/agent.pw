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

function trimTrailingSlash(pathname: string) {
  if (pathname.length > 1 && pathname.endsWith('/')) {
    return pathname.slice(0, -1)
  }
  return pathname
}

function notionResourceAlias(resource: string) {
  const url = new URL(resource)
  const pathname = trimTrailingSlash(url.pathname)

  if (url.origin === 'https://mcp.notion.com' && pathname === '/mcp') {
    return 'https://api.notion.com/'
  }

  if (url.origin === 'https://api.notion.com') {
    return 'https://mcp.notion.com/mcp'
  }

  return null
}

export function matchingResources(resource: string) {
  const normalized = normalizeResource(resource)
  const matches = new Set([normalized])
  const notionAlias = notionResourceAlias(normalized)
  if (notionAlias) {
    matches.add(notionAlias)
  }
  return [...matches]
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
