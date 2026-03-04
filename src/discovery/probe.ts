import type { ProbeResult } from './types'

const PROBE_TIMEOUT = 2000

const OPENAPI_PATHS = [
  '/.well-known/openapi.json',
  '/openapi.json',
  '/openapi.yaml',
  '/swagger.json',
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

async function probeGraphQL(baseUrl: string): Promise<string | null> {
  const base = baseUrl.replace(/\/$/, '')
  const endpoints = [`${base}/graphql`, `${base}`]

  for (const url of endpoints) {
    const res = await fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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

export async function probeService(
  baseUrl: string,
  apiType?: string,
): Promise<ProbeResult> {
  const result: ProbeResult = {
    apiType: (apiType as ProbeResult['apiType']) ?? 'unknown',
    authDetected: [],
  }

  console.log(`[probe] probing ${baseUrl} (hint: ${apiType ?? 'unknown'})`)

  // Run probes in parallel
  const [openApi, graphql, docsUrl, oauthWellKnown] = await Promise.all([
    apiType !== 'graphql' ? probeOpenApi(baseUrl) : Promise.resolve(null),
    apiType !== 'rest' ? probeGraphQL(baseUrl) : Promise.resolve(null),
    probeDocsUrl(baseUrl),
    probeOAuthWellKnown(baseUrl),
  ])

  if (openApi) {
    result.specUrl = openApi.specUrl
    result.specContent = openApi.specContent
    if (result.apiType === 'unknown') result.apiType = 'rest'

    if (!oauthWellKnown) {
      try {
        const spec = JSON.parse(openApi.specContent) as Record<string, unknown>
        const oauthFromSpec = extractOAuthFromOpenApiSpec(spec)
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

  return result
}
