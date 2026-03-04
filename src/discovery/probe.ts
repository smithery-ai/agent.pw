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
  const [openApi, graphql, docsUrl] = await Promise.all([
    apiType !== 'graphql' ? probeOpenApi(baseUrl) : Promise.resolve(null),
    apiType !== 'rest' ? probeGraphQL(baseUrl) : Promise.resolve(null),
    probeDocsUrl(baseUrl),
  ])

  if (openApi) {
    result.specUrl = openApi.specUrl
    result.specContent = openApi.specContent
    if (result.apiType === 'unknown') result.apiType = 'rest'
  }

  if (graphql) {
    result.graphqlSchema = graphql
    if (result.apiType === 'unknown') result.apiType = 'graphql'
  }

  if (docsUrl) {
    result.docsUrl = docsUrl
  }

  return result
}
