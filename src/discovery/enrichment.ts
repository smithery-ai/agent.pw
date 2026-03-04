import { generateText, stepCountIs, tool, type ToolSet } from 'ai'
import { createAmazonBedrock } from '@ai-sdk/amazon-bedrock'
import { createAnthropic } from '@ai-sdk/anthropic'
import { createMCPClient } from '@ai-sdk/mcp'
import { z } from 'zod'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage, listDocPages } from '../db/queries'
import { runDeterministicDiscovery } from './deterministic'

const BEDROCK_MODEL = 'anthropic.claude-opus-4-6-20250514-v1:0'
const ANTHROPIC_MODEL = 'claude-opus-4-6'
const MAX_STEPS = 50

function createModel(ctx: PipelineContext) {
  if (ctx.awsAccessKeyId && ctx.awsSecretAccessKey) {
    const bedrock = createAmazonBedrock({
      accessKeyId: ctx.awsAccessKeyId,
      secretAccessKey: ctx.awsSecretAccessKey,
      region: ctx.awsRegion ?? 'us-east-1',
    })
    return bedrock(BEDROCK_MODEL)
  }

  if (ctx.anthropicApiKey) {
    const anthropic = createAnthropic({
      apiKey: ctx.anthropicApiKey,
      ...(ctx.anthropicBaseUrl && { baseURL: ctx.anthropicBaseUrl }),
    })
    return anthropic(ANTHROPIC_MODEL)
  }

  return null
}

// ─── Skill: Adapted from mcp-factory get-api-spec + crawl-docs ──────────────

function buildDiscoverySystemPrompt(ctx: PipelineContext) {
  const serviceName = ctx.service.displayName ?? ctx.hostname
  const baseUrl = ctx.service.baseUrl

  return `You are a thorough API documentation agent for ${serviceName} (${baseUrl}).

Your job is to discover this API's full surface area and generate a structured sitemap. You have tools for web search, URL fetching, deterministic spec parsing, and writing doc pages. Prefer calling scripts (like parse_openapi_spec) over manually generating output whenever possible.

## Discovery Strategy (try in order)

### 1. Find an OpenAPI/Swagger spec
- APIs.guru: fetch \`https://api.apis.guru/v2/{domain}.json\` (e.g. stripe.com, zoom.us). Check \`x-origin[].url\` for the upstream source URL and fetch the spec from there.
- Web search: \`"{serviceName} openapi spec" OR "{serviceName} swagger" site:github.com\`
- ReadMe.com-hosted docs: Fetch any docs page, look for \`apiRegistries\` UUID in the HTML config, then fetch \`https://dash.readme.com/api/v1/api-registry/{uuid}\`
- Probe common URL patterns: \`{baseUrl}/openapi.json\`, \`/v1/openapi.json\`, \`/v2/openapi.json\`, \`/swagger.json\`, \`/api-docs\`, \`/.well-known/openapi\`
- HTML parsing: Fetch docs pages, look for \`spec-url="..."\` (Redoc), \`url:\` in SwaggerUI config, \`openapi\` references in script tags

**If you find a spec URL, call \`parse_openapi_spec\` with the URL.** This runs a deterministic parser that generates all pages automatically — much better than manual generation.

### 2. If no spec, crawl documentation
Try these strategies to find the docs structure:

1. **llms.txt** (best): Try \`{docsUrl}/llms.txt\` and \`{docsUrl}/llms-full.txt\`. Many modern docs sites publish these (Stripe, Shopify, Mintlify-powered). If \`llms-full.txt\` exists with actual content, you may have everything you need.

2. **Direct fetch**: Fetch the main API reference page. If server-rendered (not SPA), the sidebar/navigation contains the full section map.

3. **Sitemap.xml**: Try \`{docsUrl}/sitemap.xml\`, filter for API reference paths.

4. **Web search**: \`site:{docsHost}/api/\` with keywords like "list create update delete", "users accounts billing", "webhooks events". Expect 3-5 queries for good coverage.

For each docs section found, use \`fetch_url\` to read it and extract endpoint information.

### 3. Generate sitemap pages
For every resource group you discover, call \`write_doc_page\` with the structured content.

## Output Format

Create these pages:

**\`sitemap/index.json\`** (L0: Service overview):
\`\`\`json
{
  "level": 0,
  "service": "${serviceName}",
  "hostname": "${ctx.hostname}",
  "api_type": "rest",
  "base_url": "/${ctx.hostname}",
  "description": "One paragraph description of the API",
  "auth": [{"type": "api_key", "setup_url": "/auth/${ctx.hostname}"}],
  "docs_url": "https://..."
}
\`\`\`

**\`sitemap/resources.json\`** (L1: Resource catalog):
\`\`\`json
{
  "level": 1,
  "resources": [
    { "name": "Resource Name", "slug": "resource-name", "description": "Brief description", "common_operations": [{ "method": "GET", "path": "/resource", "summary": "List resources" }] }
  ]
}
\`\`\`

**\`sitemap/{slug}.json\`** (L2: Resource detail, one per resource):
\`\`\`json
{
  "level": 2,
  "resource": "Resource Name",
  "description": "Detailed description",
  "operations": [
    { "method": "GET", "path": "/resource", "summary": "List all resources", "slug": "list-resources", "docs_url": "https://..." }
  ]
}
\`\`\`

## Rules
- **Never fabricate endpoints** — only document what you find in actual docs or specs
- **Prefer scripts**: If you find an OpenAPI spec, call \`parse_openapi_spec\` instead of manually parsing
- **Be thorough**: Cover the full API surface area, not just the first few resources
- **Include docs_url**: For each operation, link to the official documentation page
- **Quality over speed**: Take as many steps as needed to produce accurate, complete documentation`
}

// ─── Tools ───────────────────────────────────────────────────────────────────

function buildTools(ctx: PipelineContext) {
  return {
    write_doc_page: tool({
      description:
        'Write a sitemap page. The content should be a structured JSON object matching the page schema (L0 index, L1 resources, or L2 resource detail).',
      inputSchema: z.object({
        path: z.string().describe('Page path, e.g. "sitemap/issues.json"'),
        content: z.record(z.string(), z.unknown()).describe('The page content object (will be JSON-stringified and stored)'),
      }),
      execute: async (input) => {
        await upsertDocPage(ctx.db, ctx.hostname, input.path, JSON.stringify(input.content), 'enriched')
        return `Page written: ${input.path}`
      },
    }),

    fetch_url: tool({
      description:
        'Fetch a URL and return its content. Use for reading documentation pages, downloading specs, checking if URLs exist. Returns text content (HTML, JSON, YAML, etc.).',
      inputSchema: z.object({
        url: z.string().describe('The URL to fetch'),
      }),
      execute: async (input) => {
        try {
          const res = await fetch(input.url, {
            headers: { 'User-Agent': 'Warden/1.0 (API Discovery)' },
            signal: AbortSignal.timeout(10_000),
          })
          if (!res.ok) return `HTTP ${res.status} ${res.statusText}`
          const text = await res.text()
          // Truncate very large responses to avoid context overflow
          if (text.length > 100_000) {
            return text.slice(0, 100_000) + '\n\n[truncated — response was ' + text.length + ' chars]'
          }
          return text
        } catch (e) {
          return `Fetch failed: ${e instanceof Error ? e.message : String(e)}`
        }
      },
    }),

    parse_openapi_spec: tool({
      description:
        'Deterministic script: Fetch an OpenAPI/Swagger spec from a URL, parse it into structured sitemap pages, and write them to the database. This is the preferred way to generate pages when a spec is available — much more accurate than manual generation. Returns a summary of what was generated.',
      inputSchema: z.object({
        url: z.string().describe('URL of the OpenAPI/Swagger spec (JSON or YAML)'),
      }),
      execute: async (input) => {
        try {
          const res = await fetch(input.url, {
            headers: { 'User-Agent': 'Warden/1.0 (API Discovery)' },
            signal: AbortSignal.timeout(30_000),
          })
          if (!res.ok) return `Failed to fetch spec: HTTP ${res.status}`
          const text = await res.text()

          // Build a minimal ProbeResult with the spec content
          const probe = {
            apiType: 'rest' as const,
            specContent: text,
            specUrl: input.url,
            docsUrl: ctx.service.docsUrl ?? undefined,
            externalDocsUrls: ctx.externalDocsUrls ?? [],
            authDetected: [] as string[],
          }

          const result = await runDeterministicDiscovery(ctx, probe)
          return `Spec parsed successfully. ${result.pagesWritten} pages written, ${result.resourcesFound.length} resources found: ${result.resourcesFound.join(', ')}`
        } catch (e) {
          return `Spec parsing failed: ${e instanceof Error ? e.message : String(e)}`
        }
      },
    }),
  }
}

/** Collect all available docs URLs for a service */
function collectDocsUrls(ctx: PipelineContext): string[] {
  const urls: string[] = []
  if (ctx.service.docsUrl) urls.push(ctx.service.docsUrl)
  if (ctx.externalDocsUrls) {
    for (const url of ctx.externalDocsUrls) {
      if (!urls.includes(url)) urls.push(url)
    }
  }
  return urls
}

// ─── Main Discovery Agent ────────────────────────────────────────────────────

/**
 * Run the full discovery agent for a service.
 * Uses Opus with up to 50 steps to thoroughly discover and document the API.
 * This replaces the old enrichPage/generateSitemapFromWeb split.
 */
export async function runDiscoveryAgent(ctx: PipelineContext) {
  const model = createModel(ctx)
  if (!model) return

  console.log(`[discovery-agent] starting for ${ctx.hostname}`)

  const docsUrls = collectDocsUrls(ctx)

  // Check what pages already exist
  const existingPages = await listDocPages(ctx.db, ctx.hostname)
  const existingPaths = existingPages.map(p => p.path)

  let prompt = `Discover and document the API at ${ctx.hostname} (${ctx.service.baseUrl}).`

  if (docsUrls.length > 0) {
    prompt += `\n\nKnown documentation sources:\n${docsUrls.map(u => `- ${u}`).join('\n')}`
  }

  if (ctx.service.apiType === 'graphql') {
    prompt += `\n\nThis is a GraphQL API. Look for GraphQL documentation and schema.`
  }

  if (existingPaths.length > 0) {
    prompt += `\n\nExisting pages (may need enrichment): ${existingPaths.join(', ')}`
    // Include current skeleton content for context
    for (const page of existingPages) {
      if (page.status === 'skeleton' && page.content && page.path.startsWith('sitemap/')) {
        prompt += `\n\nCurrent ${page.path}:\n${page.content}`
      }
    }
  }

  prompt += `\n\nStart by searching for an OpenAPI spec. If found, use parse_openapi_spec to generate pages deterministically. Then enrich pages with descriptions and doc_url links by searching the documentation.`

  // Build tools: local + Exa MCP
  let tools: ToolSet = buildTools(ctx)
  let mcpClient: Awaited<ReturnType<typeof createMCPClient>> | null = null

  try {
    mcpClient = await createMCPClient({
      transport: {
        type: 'sse',
        url: 'https://mcp.exa.ai/mcp?tools=web_search_exa,crawling_exa',
      },
    })
    const mcpTools = await mcpClient.tools()
    tools = { ...tools, ...mcpTools }
    console.log(`[discovery-agent] ${ctx.hostname} exa tools loaded`)
  } catch (e) {
    console.error(`[discovery-agent] ${ctx.hostname} exa MCP connection failed:`, e)
  }

  try {
    const result = await generateText({
      model,
      stopWhen: stepCountIs(MAX_STEPS),
      system: buildDiscoverySystemPrompt(ctx),
      prompt,
      tools,
      onStepFinish: ({ toolCalls }) => {
        if (toolCalls?.length) {
          for (const tc of toolCalls) {
            console.log(`[discovery-agent] ${ctx.hostname} tool_use: ${tc.toolName}`)
          }
        }
      },
    })

    console.log(`[discovery-agent] ${ctx.hostname} done (${result.steps.length} steps)`)
  } finally {
    if (mcpClient) await mcpClient.close()
  }
}

// ─── Legacy exports for backward compatibility ───────────────────────────────

/** @deprecated Use runDiscoveryAgent instead */
export async function enrichPage(ctx: PipelineContext, pagePath: string) {
  const model = createModel(ctx)
  if (!model) return

  const page = await getDocPage(ctx.db, ctx.hostname, pagePath)
  if (!page || !page.content) return

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} starting`)

  let tools: ToolSet = buildTools(ctx)
  let mcpClient: Awaited<ReturnType<typeof createMCPClient>> | null = null

  try {
    mcpClient = await createMCPClient({
      transport: {
        type: 'sse',
        url: 'https://mcp.exa.ai/mcp?tools=web_search_exa,crawling_exa',
      },
    })
    const mcpTools = await mcpClient.tools()
    tools = { ...tools, ...mcpTools }
  } catch (e) {
    console.error(`[enrichment] ${ctx.hostname}/${pagePath} exa MCP connection failed:`, e)
  }

  const docsUrls = collectDocsUrls(ctx)

  try {
    const result = await generateText({
      model,
      stopWhen: stepCountIs(MAX_STEPS),
      system: buildDiscoverySystemPrompt(ctx),
      prompt: `Enrich this sitemap page by adding descriptions and doc URLs.\n\nPage: ${pagePath}\nCurrent content:\n${page.content}\n\n${docsUrls.length > 0 ? `Known docs:\n${docsUrls.map(u => `- ${u}`).join('\n')}\n\n` : ''}Search for official API docs, then call write_doc_page to save "${pagePath}".`,
      tools,
      onStepFinish: ({ toolCalls }) => {
        if (toolCalls?.length) {
          for (const tc of toolCalls) {
            console.log(`[enrichment] ${ctx.hostname}/${pagePath} tool_use: ${tc.toolName}`)
          }
        }
      },
    })
    console.log(`[enrichment] ${ctx.hostname}/${pagePath} done (${result.steps.length} steps)`)
  } finally {
    if (mcpClient) await mcpClient.close()
  }
}

/** @deprecated Use runDiscoveryAgent instead */
export async function generateSitemapFromWeb(ctx: PipelineContext) {
  return runDiscoveryAgent(ctx)
}

export async function enrichPages(ctx: PipelineContext, paths: string[]) {
  for (const path of paths) {
    try {
      await enrichPage(ctx, path)
    } catch (e) {
      console.error(`[discovery] enrichment failed for ${ctx.hostname}/${path}:`, e)
    }
  }
}
