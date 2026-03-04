import type { ProbeResult } from './types'

const PROBE_TIMEOUT = 2000

export interface ProbeOptions {
  authHeaders?: Record<string, string>
}

const OPENAPI_PATHS = [
  // Well-known
  '/.well-known/openapi.json',
  '/.well-known/openapi.yaml',
  // Root-level
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
  '/swagger.yaml',
  // Versioned
  '/api/v1/openapi.json',
  '/api/v2/openapi.json',
  '/api/v3/openapi.json',
  '/v1/openapi.json',
  '/v2/openapi.json',
  '/v3/openapi.json',
  '/api/v1/swagger.json',
  '/api/v2/swagger.json',
  '/api/v3/swagger.json',
  // Common doc endpoints that serve specs
  '/api-docs',
  '/api/openapi',
  '/api/swagger',
  '/api/docs/openapi.json',
  '/api/docs/swagger.json',
  '/docs/openapi.json',
  '/api/docs',
  '/docs',
]

const GRAPHQL_INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        type { name kind ofType { name kind } }
        args { name description type { name kind ofType { name kind } } }
      }
    }
  }
}`

function extractOAuthFromOpenApiSpec(spec: Record<string, unknown>) {
  const securitySchemes = (
    (spec.components as Record<string, unknown> | undefined)?.securitySchemes ??
    spec.securityDefinitions
  ) as Record<string, unknown> | undefined

  if (!securitySchemes) return null

  for (const scheme of Object.values(securitySchemes)) {
    const s = scheme as Record<string, unknown>
    if (s.type !== 'oauth2') continue

    const flows = s.flows as Record<string, unknown> | undefined
    if (flows) {
      for (const flow of Object.values(flows)) {
        const f = flow as Record<string, unknown>
        const authorizeUrl = f.authorizationUrl
        const tokenUrl = f.tokenUrl
        if (typeof authorizeUrl !== 'string' || typeof tokenUrl !== 'string') continue
        const scopesObj = f.scopes as Record<string, unknown> | undefined
        const scopes = scopesObj ? Object.keys(scopesObj).join(' ') : undefined
        return { authorizeUrl, tokenUrl, scopes: scopes || undefined }
      }
      continue
    }

    // Swagger 2.0
    const authorizeUrl = s.authorizationUrl
    const tokenUrl = s.tokenUrl
    if (typeof authorizeUrl === 'string' && typeof tokenUrl === 'string') {
      const scopesObj = s.scopes as Record<string, unknown> | undefined
      const scopes = scopesObj ? Object.keys(scopesObj).join(' ') : undefined
      return { authorizeUrl, tokenUrl, scopes: scopes || undefined }
    }
  }

  return null
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT)
  try {
    const res = await fetch(url, { ...init, signal: controller.signal })
    return res
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

async function probeOpenApi(baseUrl: string): Promise<{ specUrl: string; specContent: string } | null> {
  const base = baseUrl.replace(/\/$/, '')

  const results = await Promise.allSettled(
    OPENAPI_PATHS.map(async path => {
      const url = `${base}${path}`
      const res = await fetchWithTimeout(url)
      if (!res || !res.ok) return null

      const contentType = res.headers.get('content-type') ?? ''
      const text = await res.text()

      // Check if it looks like an OpenAPI spec
      if (
        contentType.includes('json') ||
        contentType.includes('yaml') ||
        text.includes('"openapi"') ||
        text.includes('"swagger"') ||
        text.includes('openapi:')
      ) {
        return { specUrl: url, specContent: text }
      }
      return null
    }),
  )

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      return result.value
    }
  }
  return null
}

async function probeGraphQL(baseUrl: string, authHeaders?: Record<string, string>): Promise<string | null> {
  const base = baseUrl.replace(/\/$/, '')
  const endpoints = [`${base}/graphql`, `${base}`]

  for (const url of endpoints) {
    const res = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({ query: GRAPHQL_INTROSPECTION_QUERY }),
    })

    if (!res || !res.ok) continue

    const text = await res.text()
    if (text.includes('__schema')) {
      return text
    }
  }

  return null
}

async function probeDocsUrl(baseUrl: string): Promise<string | null> {
  const base = baseUrl.replace(/\/$/, '')
  const paths = ['/docs', '/api/docs', '/documentation', '/reference']

  for (const path of paths) {
    const url = `${base}${path}`
    const res = await fetchWithTimeout(url, { method: 'HEAD' })
    if (res?.ok) return url
  }

  return null
}

export async function probeOAuthWellKnown(
  baseUrl: string,
): Promise<{ authorizeUrl: string; tokenUrl: string; scopes?: string } | null> {
  const base = baseUrl.replace(/\/$/, '')
  const paths = [
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
  ]

  for (const path of paths) {
    const url = `${base}${path}`
    const res = await fetchWithTimeout(url)
    if (!res || !res.ok) continue

    try {
      const data = (await res.json()) as Record<string, unknown>
      const authorizeUrl = data.authorization_endpoint
      const tokenUrl = data.token_endpoint
      if (typeof authorizeUrl !== 'string' || typeof tokenUrl !== 'string') {
        continue
      }

      const scopes =
        Array.isArray(data.scopes_supported)
          ? data.scopes_supported.filter((s): s is string => typeof s === 'string').join(' ')
          : undefined

      return { authorizeUrl, tokenUrl, scopes: scopes || undefined }
    } catch {
      // ignore malformed response
    }
  }

  return null
}

/** Extract root domain from API hostname (e.g., api.linear.app → linear.app) */
function extractRootDomain(hostname: string): string {
  const parts = hostname.split('.')
  if (parts.length > 2 && (parts[0] === 'api' || parts[0] === 'app')) {
    return parts.slice(1).join('.')
  }
  return hostname
}

/** Probe external domains for documentation (e.g., docs.linear.app, developers.github.com) */
async function probeExternalDocs(hostname: string): Promise<string[]> {
  const root = extractRootDomain(hostname)
  if (root === hostname) return []

  const candidates = [
    `https://docs.${root}`,
    `https://developers.${root}`,
    `https://developer.${root}`,
    `https://${root}/docs`,
    `https://${root}/api-reference`,
  ]

  const results = await Promise.allSettled(
    candidates.map(async url => {
      const res = await fetchWithTimeout(url, { method: 'HEAD' })
      return res && res.ok ? url : null
    }),
  )

  return results
    .filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value)
}

/** Look up an OpenAPI spec from the APIs.guru public registry */
async function probeApisGuru(hostname: string): Promise<{ specUrl: string; specContent: string } | null> {
  const provider = extractRootDomain(hostname)
  const url = `https://api.apis.guru/v2/${provider}.json`
  const res = await fetchWithTimeout(url)
  if (!res || !res.ok) return null

  try {
    const data = (await res.json()) as Record<string, unknown>
    const apis = data.apis as Record<string, Record<string, unknown>> | undefined
    if (!apis) return null

    // Find the best match — prefer entries whose key contains our hostname
    const entries = Object.entries(apis)
    const match = entries.find(([key]) => key.includes(hostname)) ?? entries[0]
    if (!match) return null

    const [, api] = match
    const specUrl = (api.swaggerUrl as string) ?? (api.openapiUrl as string)
    if (!specUrl) return null

    const specRes = await fetchWithTimeout(specUrl)
    if (!specRes || !specRes.ok) return null
    const specContent = await specRes.text()

    if (
      specContent.includes('"openapi"') ||
      specContent.includes('"swagger"') ||
      specContent.includes('openapi:')
    ) {
      return { specUrl, specContent }
    }
  } catch {
    // ignore malformed response
  }
  return null
}

export async function probeService(
  baseUrl: string,
  apiType?: string,
  hostname?: string,
  options?: ProbeOptions,
): Promise<ProbeResult> {
  const result: ProbeResult = {
    apiType: (apiType as ProbeResult['apiType']) ?? 'unknown',
    externalDocsUrls: [],
    authDetected: [],
  }

  console.log(`[probe] probing ${baseUrl} (hint: ${apiType ?? 'unknown'})`)

  // Derive hostname from baseUrl if not provided
  const host = hostname ?? new URL(baseUrl).hostname

  // Run probes in parallel
  const [openApi, graphql, docsUrl, oauthWellKnown, externalDocs, apisGuru] = await Promise.all([
    apiType !== 'graphql' ? probeOpenApi(baseUrl) : Promise.resolve(null),
    apiType !== 'rest' ? probeGraphQL(baseUrl, options?.authHeaders) : Promise.resolve(null),
    probeDocsUrl(baseUrl),
    probeOAuthWellKnown(baseUrl),
    probeExternalDocs(host),
    apiType !== 'graphql' ? probeApisGuru(host) : Promise.resolve(null),
  ])

  // Prefer direct spec over APIs.guru registry
  const spec = openApi ?? apisGuru

  if (spec) {
    result.specUrl = spec.specUrl
    result.specContent = spec.specContent
    if (result.apiType === 'unknown') result.apiType = 'rest'
    if (apisGuru && !openApi) {
      console.log(`[probe] found spec via APIs.guru registry: ${spec.specUrl}`)
    }

    if (!oauthWellKnown) {
      try {
        const parsed = JSON.parse(spec.specContent) as Record<string, unknown>
        const oauthFromSpec = extractOAuthFromOpenApiSpec(parsed)
        if (oauthFromSpec) {
          result.authDetected.push('oauth')
          result.oauthMeta = {
            authorizeUrl: oauthFromSpec.authorizeUrl,
            tokenUrl: oauthFromSpec.tokenUrl,
            scopes: oauthFromSpec.scopes,
            source: 'openapi',
          }
        }
      } catch {
        // Skip non-JSON OpenAPI docs for oauth extraction.
      }
    }
  }

  if (graphql) {
    result.graphqlSchema = graphql
    if (result.apiType === 'unknown') result.apiType = 'graphql'
  }

  if (docsUrl) {
    result.docsUrl = docsUrl
  }

  if (oauthWellKnown) {
    result.authDetected.push('oauth')
    result.oauthMeta = {
      authorizeUrl: oauthWellKnown.authorizeUrl,
      tokenUrl: oauthWellKnown.tokenUrl,
      scopes: oauthWellKnown.scopes,
      source: 'well_known',
    }
  }

  result.externalDocsUrls = externalDocs
  if (!result.docsUrl && externalDocs.length > 0) {
    result.docsUrl = externalDocs[0]
  }

  console.log(`[probe] external docs for ${host}: ${externalDocs.length > 0 ? externalDocs.join(', ') : 'none'}`)

  return result
}
