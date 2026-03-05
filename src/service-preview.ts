interface HostIconOverride {
  pattern: RegExp
  iconHost: string
  fallback: string
}

const HOST_ICON_OVERRIDES: HostIconOverride[] = [
  { pattern: /(^|\.)github\.com$/i, iconHost: 'github.com', fallback: 'GH' },
  { pattern: /(^|\.)gitlab\.com$/i, iconHost: 'gitlab.com', fallback: 'GL' },
  { pattern: /(^|\.)notion\.(so|site)$/i, iconHost: 'notion.so', fallback: 'NO' },
  { pattern: /(^|\.)slack\.com$/i, iconHost: 'slack.com', fallback: 'SL' },
  { pattern: /(^|\.)linear\.app$/i, iconHost: 'linear.app', fallback: 'LI' },
  { pattern: /(^|\.)posthog\.com$/i, iconHost: 'posthog.com', fallback: 'PH' },
  { pattern: /(^|\.)stripe\.com$/i, iconHost: 'stripe.com', fallback: 'ST' },
  { pattern: /(^|\.)openai\.com$/i, iconHost: 'openai.com', fallback: 'OA' },
  { pattern: /(^|\.)anthropic\.com$/i, iconHost: 'anthropic.com', fallback: 'AN' },
  { pattern: /(^|\.)googleapis\.com$/i, iconHost: 'google.com', fallback: 'GO' },
  { pattern: /(^|\.)atlassian\.net$/i, iconHost: 'atlassian.com', fallback: 'AT' },
]

export interface ServiceIconPreview {
  source: 'hostname-favicon' | 'custom'
  host?: string
  url?: string
  fallback: string
}

function normalizeHostname(hostname: string) {
  return hostname.trim().toLowerCase().replace(/:\d+$/, '')
}

function monogramFromText(text: string) {
  const words = text
    .trim()
    .toUpperCase()
    .split(/[^A-Z0-9]+/)
    .filter(Boolean)

  if (words.length >= 2) {
    return `${words[0][0]}${words[1][0]}`
  }

  if (words.length === 1) {
    return words[0].slice(0, 2)
  }

  return 'API'
}

function defaultMonogram(hostname: string, displayName?: string) {
  if (displayName && displayName.trim().length > 0) {
    return monogramFromText(displayName)
  }

  const core = normalizeHostname(hostname).replace(/^(api|www|app|gateway|m)\./, '')
  const firstLabel = core.split('.')[0] ?? core
  const cleaned = firstLabel.replace(/[^a-z0-9]/gi, '')
  return cleaned.length > 0 ? cleaned.slice(0, 2).toUpperCase() : 'API'
}

function findOverride(hostname: string) {
  const normalized = normalizeHostname(hostname)
  return HOST_ICON_OVERRIDES.find(override => override.pattern.test(normalized))
}

export function inferServiceIconPreview(hostname: string, displayName?: string): ServiceIconPreview {
  const normalized = normalizeHostname(hostname)
  const override = findOverride(normalized)
  const iconHost = override?.iconHost ?? normalized.replace(/^(api|www|app|gateway|m)\./, '')
  const fallback = override?.fallback ?? defaultMonogram(normalized, displayName)

  return {
    source: 'hostname-favicon',
    host: iconHost,
    url: `https://icons.duckduckgo.com/ip3/${iconHost}.ico`,
    fallback,
  }
}
