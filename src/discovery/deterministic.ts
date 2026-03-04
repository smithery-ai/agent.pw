import type { PipelineContext, ProbeResult, DocIndexPage, DocResourcesPage, DocResourceDetailPage, DocMeta } from './types'
import { upsertDocPage, upsertService } from '../db/queries'

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
  const resourceMap = new Map<string, { method: string; path: string; summary: string; operationId?: string }[]>()

  if (paths) {
    for (const [path, methods] of Object.entries(paths)) {
      for (const [method, op] of Object.entries(methods)) {
        if (method.startsWith('x-') || method === 'parameters') continue
        const operation = op as Record<string, unknown>
        const tags = (operation.tags as string[]) ?? []
        const resourceName = tags[0] ?? path.split('/').filter(Boolean)[0] ?? 'default'
        const slug = resourceName.toLowerCase().replace(/\s+/g, '-')

        if (!resourceMap.has(slug)) resourceMap.set(slug, [])
        resourceMap.get(slug)!.push({
          method: method.toUpperCase(),
          path,
          summary: (operation.summary as string) ?? (operation.description as string) ?? '',
          operationId: operation.operationId as string | undefined,
        })
      }
    }
  }

  const supported: string[] = ctx.service.supportedAuthMethods
    ? JSON.parse(ctx.service.supportedAuthMethods)
    : []
  const supportedSet = new Set(supported)
  if (oauthMeta) supportedSet.add('oauth')
  const supportedMethods = Array.from(supportedSet)

  // Build L0 index
  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: 'rest',
    base_url: `/${ctx.hostname}`,
    description: (info?.description as string) ?? ctx.service.description ?? '',
    auth: supportedMethods.map(m => ({
      type: m,
      setup_url: `/auth/${ctx.hostname}`,
    })),
    docs_url: ctx.service.docsUrl ?? undefined,
  }

  // Pick first GET endpoint as quick_start
  for (const ops of resourceMap.values()) {
    const getOp = ops.find(o => o.method === 'GET')
    if (getOp) {
      indexPage.quick_start = {
        method: 'GET',
        path: getOp.path,
        description: getOp.summary || `List ${getOp.path}`,
      }
      break
    }
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
    { path: 'docs/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'docs/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
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
      })),
    }
    pages.push({
      path: `docs/${slug}.json`,
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
  const resourceMap = new Map<string, { method: string; path: string; summary: string; slug: string }[]>()

  function addOps(fields: typeof queryType extends undefined ? never : NonNullable<typeof queryType>['fields'], method: string) {
    if (!fields) return
    for (const field of fields) {
      // Derive resource from field name (e.g., "issues" -> "issues", "createIssue" -> "issue")
      const name = field.name
      const resource = name
        .replace(/^(create|update|delete|get|list|find|remove|add)/, '')
        .replace(/^./, c => c.toLowerCase()) || name
      const slug = resource.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'misc'

      if (!resourceMap.has(slug)) resourceMap.set(slug, [])
      resourceMap.get(slug)!.push({
        method,
        path: field.name,
        summary: field.description ?? '',
        slug: field.name,
      })
    }
  }

  addOps(queryType?.fields, 'QUERY')
  addOps(mutationType?.fields, 'MUTATION')

  const supported: string[] = ctx.service.supportedAuthMethods
    ? JSON.parse(ctx.service.supportedAuthMethods)
    : []

  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: 'graphql',
    base_url: `/${ctx.hostname}`,
    description: ctx.service.description ?? 'GraphQL API',
    auth: supported.map(m => ({
      type: m,
      setup_url: `/auth/${ctx.hostname}`,
    })),
    docs_url: ctx.service.docsUrl ?? undefined,
  }

  // Quick start: first query
  const firstQuery = queryType?.fields?.[0]
  if (firstQuery) {
    indexPage.quick_start = {
      method: 'POST',
      path: '/graphql',
      description: `Query: ${firstQuery.name} — ${firstQuery.description ?? ''}`.trim(),
    }
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
    { path: 'docs/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'docs/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
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
      })),
    }
    pages.push({
      path: `docs/${slug}.json`,
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
  const supported: string[] = ctx.service.supportedAuthMethods
    ? JSON.parse(ctx.service.supportedAuthMethods)
    : []

  const indexPage: DocIndexPage = {
    level: 0,
    service: ctx.service.displayName ?? ctx.hostname,
    hostname: ctx.hostname,
    api_type: (ctx.service.apiType as 'rest' | 'graphql') ?? 'unknown',
    base_url: `/${ctx.hostname}`,
    description: ctx.service.description ?? '',
    auth: supported.map(m => ({
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
    { path: 'docs/index.json', content: JSON.stringify(indexPage), status: 'skeleton' },
    { path: 'docs/resources.json', content: JSON.stringify(resourcesPage), status: 'skeleton' },
  ]
}

// ─── Main ────────────────────────────────────────────────────────────────────

export async function runDeterministicDiscovery(
  ctx: PipelineContext,
  probe: ProbeResult,
): Promise<DeterministicResult> {
  if (probe.oauthMeta) {
    const currentSupported: string[] = ctx.service.supportedAuthMethods
      ? JSON.parse(ctx.service.supportedAuthMethods)
      : []
    const supportedSet = new Set(currentSupported)
    supportedSet.add('oauth')
    supportedSet.add('api_key')

    await upsertService(ctx.db, ctx.hostname, {
      baseUrl: ctx.service.baseUrl,
      authMethod: 'bearer',
      headerName: ctx.service.headerName ?? 'Authorization',
      headerScheme: ctx.service.headerScheme ?? 'Bearer',
      oauthAuthorizeUrl: probe.oauthMeta.authorizeUrl,
      oauthTokenUrl: probe.oauthMeta.tokenUrl,
      oauthScopes: probe.oauthMeta.scopes ?? ctx.service.oauthScopes ?? undefined,
      supportedAuthMethods: JSON.stringify(Array.from(supportedSet)),
    })

    ctx.service.oauthAuthorizeUrl = probe.oauthMeta.authorizeUrl
    ctx.service.oauthTokenUrl = probe.oauthMeta.tokenUrl
    ctx.service.oauthScopes = probe.oauthMeta.scopes ?? ctx.service.oauthScopes
    ctx.service.supportedAuthMethods = JSON.stringify(Array.from(supportedSet))
  }

  let pages: { path: string; content: string; status: string }[]
  let result: DeterministicResult

  if (probe.specContent) {
    try {
      const spec = JSON.parse(probe.specContent)
      const parsed = parseOpenApi(ctx, spec)
      pages = (parsed as unknown as { _pages: typeof pages })._pages
      result = { pagesWritten: parsed.pagesWritten, resourcesFound: parsed.resourcesFound, hasSpec: true }
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

  // Write all pages to DB
  for (const page of pages) {
    await upsertDocPage(ctx.db, ctx.hostname, page.path, page.content, page.status)
  }

  // Write _meta.json
  const meta: DocMeta = {
    hostname: ctx.hostname,
    sources: [probe.specUrl, probe.docsUrl].filter(Boolean) as string[],
    api_type: probe.apiType,
    coverage: {
      total_resources: result.resourcesFound.length,
      enriched_resources: 0,
      total_operations: pages.filter(p => p.path.startsWith('docs/') && p.path !== 'docs/index.json' && p.path !== 'docs/resources.json').length,
      enriched_operations: 0,
    },
    pipeline_state: 'idle',
    staleness: { stale_pages: 0 },
  }
  await upsertDocPage(ctx.db, ctx.hostname, '_meta.json', JSON.stringify(meta), 'enriched')

  return result
}
