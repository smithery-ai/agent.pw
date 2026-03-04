import type { PipelineContext, ProbeResult, DocIndexPage, DocResourcesPage, DocResourceDetailPage, DocMeta } from './types'
import { upsertDocPage, upsertService } from '../db/queries'
import { parseAuthSchemes, getOAuthScheme, DEFAULT_API_KEY_SCHEME, type AuthScheme } from '../auth-schemes'

interface DeterministicResult {
  pagesWritten: number
  resourcesFound: string[]
  hasSpec: boolean
  oauthMeta?: {
    authorizeUrl: string
    tokenUrl: string
    scopes?: string
  }
}

function deriveAuthLabels(schemes: AuthScheme[], hasExtraOAuth = false): string[] {
  const labels = new Set<string>()
  for (const s of schemes) {
    if (s.type === 'oauth2') labels.add('oauth')
    else labels.add('api_key')
  }
  if (hasExtraOAuth) labels.add('oauth')
  if (labels.size === 0) labels.add('api_key')
  return Array.from(labels)
}

// ─── OpenAPI Parsing ─────────────────────────────────────────────────────────

function extractOAuthFromOpenApi(spec: Record<string, unknown>) {
  const oauthSchemes: { authorizeUrl: string; tokenUrl: string; scopes?: string }[] = []

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
        oauthSchemes.push({ authorizeUrl, tokenUrl, scopes: scopes || undefined })
      }
      continue
    }

    // Swagger 2.0
    const authorizeUrl = s.authorizationUrl
    const tokenUrl = s.tokenUrl
    if (typeof authorizeUrl === 'string' && typeof tokenUrl === 'string') {
      const scopesObj = s.scopes as Record<string, unknown> | undefined
      const scopes = scopesObj ? Object.keys(scopesObj).join(' ') : undefined
      oauthSchemes.push({ authorizeUrl, tokenUrl, scopes: scopes || undefined })
    }
  }

  return oauthSchemes[0] ?? null
}

function parseOpenApi(ctx: PipelineContext, spec: unknown): DeterministicResult {
  const s = spec as Record<string, unknown>
  const info = s.info as Record<string, string> | undefined
  const paths = s.paths as Record<string, Record<string, unknown>> | undefined
  const oauthMeta = extractOAuthFromOpenApi(s)

  // Group endpoints by tag or first path segment into resources
  const resourceMap = new Map<string, {
    method: string
    path: string
    summary: string
    operationId?: string
    parameters?: { name: string; type: string; required: boolean; description: string }[]
    responseCodes?: { status: number; description: string }[]
  }[]>()

  if (paths) {
    for (const [path, methods] of Object.entries(paths)) {
      const pathParams = (methods.parameters ?? []) as Record<string, unknown>[]
      for (const [method, op] of Object.entries(methods)) {
        if (method.startsWith('x-') || method === 'parameters') continue
        const operation = op as Record<string, unknown>
        const tags = (operation.tags as string[]) ?? []
        const segments = path.split('/').filter(Boolean)
        // Skip version-like segments (v1, v2, etc.) to get the actual resource name
        const firstMeaningful = segments.find(s => !/^v\d+$/i.test(s)) ?? segments[0]
        const resourceName = tags[0] ?? firstMeaningful ?? 'default'
        const slug = resourceName.toLowerCase().replace(/\s+/g, '-')

        // Extract parameters from both path-level and operation-level
        const opParams = (operation.parameters ?? []) as Record<string, unknown>[]
        const allParams = [...pathParams, ...opParams]
        const parameters = allParams.map(p => ({
          name: (p.name as string) ?? '',
          type: (p.schema as Record<string, string>)?.type ?? (p.type as string) ?? 'string',
          required: (p.required as boolean) ?? false,
          description: (p.description as string) ?? '',
        }))

        // Extract response codes
        const responses = operation.responses as Record<string, Record<string, unknown>> | undefined
        const responseCodes = responses
          ? Object.entries(responses).map(([status, resp]) => ({
              status: parseInt(status, 10),
              description: (resp.description as string) ?? '',
            })).filter(r => !isNaN(r.status))
          : undefined

        if (!resourceMap.has(slug)) resourceMap.set(slug, [])
        resourceMap.get(slug)!.push({
          method: method.toUpperCase(),
          path,
          summary: (operation.summary as string) ?? (operation.description as string) ?? '',
          operationId: operation.operationId as string | undefined,
          parameters: parameters.length > 0 ? parameters : undefined,
          responseCodes: responseCodes && responseCodes.length > 0 ? responseCodes : undefined,
        })
      }
    }
  }

  const schemes = parseAuthSchemes(ctx.service.authSchemes)
  const authLabels = deriveAuthLabels(schemes, !!oauthMeta)

  // Build L0 index
  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: 'rest',
    base_url: `/${ctx.hostname}`,
    description: (info?.description as string) ?? ctx.service.description ?? '',
    auth: authLabels.map(m => ({
      type: m,
      setup_url: `/auth/${ctx.hostname}`,
    })),
    docs_url: ctx.service.docsUrl ?? undefined,
  }

  // Build L1 resources
  const resourcesPage: DocResourcesPage = {
    level: 1,
    resources: Array.from(resourceMap.entries()).map(([slug, ops]) => ({
      name: slug.charAt(0).toUpperCase() + slug.slice(1),
      slug,
      description: '',
      common_operations: ops.slice(0, 5).map(o => ({
        method: o.method,
        path: o.path,
        summary: o.summary,
      })),
    })),
  }

  // Build L2 resource detail pages
  const pages: { path: string; content: string; status: string }[] = [
    { path: 'sitemap/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'sitemap/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
  ]

  for (const [slug, ops] of resourceMap.entries()) {
    const detailPage: DocResourceDetailPage = {
      level: 2,
      resource: slug.charAt(0).toUpperCase() + slug.slice(1),
      description: '',
      operations: ops.map(o => ({
        method: o.method,
        path: o.path,
        summary: o.summary,
        slug: (o.operationId ?? `${o.method.toLowerCase()}-${o.path}`).toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        parameters: o.parameters,
        response_codes: o.responseCodes,
      })),
    }
    pages.push({
      path: `sitemap/${slug}.json`,
      content: JSON.stringify(detailPage),
      status: 'skeleton',
    })
  }

  return {
    pagesWritten: pages.length,
    resourcesFound: Array.from(resourceMap.keys()),
    hasSpec: true,
    oauthMeta: oauthMeta ?? undefined,
    ...({ _pages: pages } as Record<string, unknown>),
  }
}

// ─── GraphQL Parsing ─────────────────────────────────────────────────────────

function parseGraphQL(ctx: PipelineContext, schemaJson: string): DeterministicResult & { _pages: { path: string; content: string; status: string }[] } {
  const data = JSON.parse(schemaJson)
  const schema = data.data?.__schema ?? data.__schema

  const queryTypeName = schema?.queryType?.name ?? 'Query'
  const mutationTypeName = schema?.mutationType?.name ?? 'Mutation'
  const types = (schema?.types ?? []) as {
    name: string
    kind: string
    description?: string
    fields?: { name: string; description?: string; type: { name?: string; kind: string }; args?: { name: string; description?: string; type: { name?: string; kind: string } }[] }[]
  }[]

  // Extract query and mutation fields as "operations"
  const queryType = types.find(t => t.name === queryTypeName)
  const mutationType = types.find(t => t.name === mutationTypeName)

  // Group by resource (heuristic: first word of field name or return type)
  const resourceMap = new Map<string, {
    method: string
    path: string
    summary: string
    slug: string
    parameters?: { name: string; type: string; required: boolean; description: string }[]
  }[]>()

  function addOps(fields: typeof queryType extends undefined ? never : NonNullable<typeof queryType>['fields'], method: string) {
    if (!fields) return
    for (const field of fields) {
      // Derive resource from field name (e.g., "issues" -> "issues", "createIssue" -> "issue")
      const name = field.name
      const resource = name
        .replace(/^(create|update|delete|get|list|find|remove|add)/, '')
        .replace(/^./, c => c.toLowerCase()) || name
      const slug = resource.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'misc'

      // Extract args as parameters
      const parameters = field.args?.map(a => ({
        name: a.name,
        type: a.type?.name ?? a.type?.kind ?? 'unknown',
        required: a.type?.kind === 'NON_NULL',
        description: a.description ?? '',
      }))

      if (!resourceMap.has(slug)) resourceMap.set(slug, [])
      resourceMap.get(slug)!.push({
        method,
        path: field.name,
        summary: field.description ?? '',
        slug: field.name,
        parameters: parameters && parameters.length > 0 ? parameters : undefined,
      })
    }
  }

  addOps(queryType?.fields, 'QUERY')
  addOps(mutationType?.fields, 'MUTATION')

  const schemes = parseAuthSchemes(ctx.service.authSchemes)
  const authLabels = deriveAuthLabels(schemes)

  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: 'graphql',
    base_url: `/${ctx.hostname}`,
    description: ctx.service.description ?? 'GraphQL API',
    auth: authLabels.map(m => ({
      type: m,
      setup_url: `/auth/${ctx.hostname}`,
    })),
    docs_url: ctx.service.docsUrl ?? undefined,
  }

  const resourcesPage: DocResourcesPage = {
    level: 1,
    resources: Array.from(resourceMap.entries()).map(([slug, ops]) => ({
      name: slug.charAt(0).toUpperCase() + slug.slice(1),
      slug,
      description: '',
      common_operations: ops.slice(0, 5).map(o => ({
        method: o.method,
        path: o.path,
        summary: o.summary,
      })),
    })),
  }

  const pages: { path: string; content: string; status: string }[] = [
    { path: 'sitemap/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'sitemap/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
  ]

  for (const [slug, ops] of resourceMap.entries()) {
    const detailPage: DocResourceDetailPage = {
      level: 2,
      resource: slug.charAt(0).toUpperCase() + slug.slice(1),
      description: '',
      operations: ops.map(o => ({
        method: o.method,
        path: o.path,
        summary: o.summary,
        slug: o.slug,
        parameters: o.parameters,
      })),
    }
    pages.push({
      path: `sitemap/${slug}.json`,
      content: JSON.stringify(detailPage),
      status: 'skeleton',
    })
  }

  return {
    pagesWritten: pages.length,
    resourcesFound: Array.from(resourceMap.keys()),
    hasSpec: true,
    _pages: pages,
  }
}

// ─── Fallback (no spec) ─────────────────────────────────────────────────────

function buildFallback(ctx: PipelineContext): { path: string; content: string; status: string }[] {
  const schemes = parseAuthSchemes(ctx.service.authSchemes)
  const authLabels = deriveAuthLabels(schemes)

  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: (ctx.service.apiType as 'rest' | 'graphql') ?? 'unknown',
    base_url: `/${ctx.hostname}`,
    description: ctx.service.description ?? '',
    auth: authLabels.map(m => ({
      type: m,
      setup_url: `/auth/${ctx.hostname}`,
    })),
    docs_url: ctx.service.docsUrl ?? undefined,
  }

  const resourcesPage: DocResourcesPage = {
    level: 1,
    resources: [],
  }

  return [
    { path: 'sitemap/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'sitemap/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
  ]
}

// ─── Main ────────────────────────────────────────────────────────────────────

export async function runDeterministicDiscovery(
  ctx: PipelineContext,
  probe: ProbeResult,
): Promise<DeterministicResult> {
  if (probe.oauthMeta && !getOAuthScheme(parseAuthSchemes(ctx.service.authSchemes))) {
    const existingSchemes = parseAuthSchemes(ctx.service.authSchemes)
    if (existingSchemes.length === 0) {
      existingSchemes.push(DEFAULT_API_KEY_SCHEME)
    }
    existingSchemes.push({
      type: 'oauth2',
      authorizeUrl: probe.oauthMeta.authorizeUrl,
      tokenUrl: probe.oauthMeta.tokenUrl,
      scopes: probe.oauthMeta.scopes,
    })

    const updatedSchemes = JSON.stringify(existingSchemes)
    await upsertService(ctx.db, ctx.hostname, {
      baseUrl: ctx.service.baseUrl,
      authSchemes: updatedSchemes,
    })

    ctx.service.authSchemes = updatedSchemes
  }

  let pages: { path: string; content: string; status: string }[]
  let result: DeterministicResult
  let specDescription: string | undefined

  if (probe.specContent) {
    try {
      const spec = JSON.parse(probe.specContent)
      const parsed = parseOpenApi(ctx, spec)
      pages = (parsed as unknown as { _pages: typeof pages })._pages
      result = { pagesWritten: parsed.pagesWritten, resourcesFound: parsed.resourcesFound, hasSpec: true }
      const info = (spec as Record<string, unknown>).info as Record<string, string> | undefined
      specDescription = info?.description
    } catch {
      pages = buildFallback(ctx)
      result = { pagesWritten: pages.length, resourcesFound: [], hasSpec: false }
    }
  } else if (probe.graphqlSchema) {
    try {
      const parsed = parseGraphQL(ctx, probe.graphqlSchema)
      pages = parsed._pages
      result = { pagesWritten: parsed.pagesWritten, resourcesFound: parsed.resourcesFound, hasSpec: true }
    } catch {
      pages = buildFallback(ctx)
      result = { pagesWritten: pages.length, resourcesFound: [], hasSpec: false }
    }
  } else {
    pages = buildFallback(ctx)
    result = { pagesWritten: pages.length, resourcesFound: [], hasSpec: false }
  }

  // Update service record with discovered metadata
  const serviceUpdate: Record<string, string | undefined> = {}
  if (probe.apiType !== 'unknown') serviceUpdate.apiType = probe.apiType
  if (probe.docsUrl) serviceUpdate.docsUrl = probe.docsUrl
  if (specDescription) serviceUpdate.description = specDescription
  if (Object.keys(serviceUpdate).length > 0) {
    await upsertService(ctx.db, ctx.hostname, { baseUrl: ctx.service.baseUrl, ...serviceUpdate })
  }

  // Write all pages to DB
  for (const page of pages) {
    await upsertDocPage(ctx.db, ctx.hostname, page.path, page.content, page.status)
  }

  // Write _meta.json
  const meta: DocMeta = {
    hostname: ctx.hostname,
    sources: [probe.specUrl, probe.docsUrl, ...(probe.externalDocsUrls ?? [])].filter(Boolean) as string[],
    api_type: probe.apiType,
    coverage: {
      total_resources: result.resourcesFound.length,
      enriched_resources: 0,
      total_operations: pages.filter(p => p.path.startsWith('sitemap/') && p.path !== 'sitemap/index.json' && p.path !== 'sitemap/resources.json').length,
      enriched_operations: 0,
    },
    pipeline_state: 'idle',
    last_full_run: new Date().toISOString(),
    staleness: { stale_pages: 0 },
  }
  await upsertDocPage(ctx.db, ctx.hostname, '_meta.json', JSON.stringify(meta), 'enriched')

  return result
}
