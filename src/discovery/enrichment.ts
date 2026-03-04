import { generateText, stepCountIs, tool, type ToolSet } from 'ai'
import { createAmazonBedrock } from '@ai-sdk/amazon-bedrock'
import { createAnthropic } from '@ai-sdk/anthropic'
import { createMCPClient } from '@ai-sdk/mcp'
import { z } from 'zod'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage } from '../db/queries'

const BEDROCK_MODEL = 'anthropic.claude-sonnet-4-6-20250514-v1:0'
const ANTHROPIC_MODEL = 'claude-sonnet-4-6'
const INITIAL_MAX_STEPS = 2
const REENRICH_MAX_STEPS = 3

function createModel(ctx: PipelineContext) {
  // Prefer Bedrock when AWS credentials are available
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

function buildSystemPrompt(ctx: PipelineContext) {
  return `You are enriching a thin API sitemap for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

Your ONLY job is to:
1. Add one-line descriptions where they are empty
2. Find and attach docs_url per operation by searching for official API documentation

Do NOT generate examples, request bodies, or response schemas.
Do NOT hallucinate endpoints or fields.
Call write_doc_page IMMEDIATELY after searching. One search, then write.`
}

function buildReenrichSystemPrompt(ctx: PipelineContext) {
  return `You are improving an API sitemap for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

Your ONLY job is to:
1. Improve empty or vague descriptions to be more specific
2. Find and attach docs_url per operation via search
3. Fix any inaccurate information

Do NOT add examples, request bodies, or response schemas.
Do NOT remove existing accurate content.
Call write_doc_page when improvements are ready.`
}

function buildEnrichmentPrompt(pagePath: string, pageContent: string, docsUrls: string[]) {
  let prompt = `Enrich this sitemap page by adding descriptions and doc URLs, then call write_doc_page.

Page: ${pagePath}
Current content:
${pageContent}
`

  if (docsUrls.length > 0) {
    prompt += `\nKnown documentation sources:\n`
    for (const url of docsUrls) {
      prompt += `- ${url}\n`
    }
  }

  prompt += `\nUse web_search_exa to find official API docs for each operation, then call write_doc_page to save "${pagePath}".`

  return prompt
}

function buildReenrichmentPrompt(pagePath: string, pageContent: string, docsUrls: string[]) {
  let prompt = `Review and improve this sitemap page. Add missing descriptions and doc URLs.

Page: ${pagePath}
Current content:
${pageContent}
`

  if (docsUrls.length > 0) {
    prompt += `\nKnown documentation sources:\n`
    for (const url of docsUrls) {
      prompt += `- ${url}\n`
    }
  }

  prompt += `\nSearch for official docs, then call write_doc_page with improvements for "${pagePath}".`

  return prompt
}

function buildTools(ctx: PipelineContext) {
  return {
    write_doc_page: tool({
      description:
        'Write an enriched sitemap page. The content should be a structured JSON object matching the page schema.',
      inputSchema: z.object({
        path: z.string().describe('Page path, e.g. "sitemap/issues.json"'),
        content: z.record(z.string(), z.unknown()).describe('The page content object (will be JSON-stringified and stored)'),
      }),
      execute: async (input) => {
        await upsertDocPage(ctx.db, ctx.hostname, input.path, JSON.stringify(input.content), 'enriched')
        return `Page written: ${input.path}`
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

export async function enrichPage(ctx: PipelineContext, pagePath: string) {
  const model = createModel(ctx)
  if (!model) return

  const page = await getDocPage(ctx.db, ctx.hostname, pagePath)
  if (!page || !page.content) return

  const isReenrich = page.status === 'enriched'

  const docsUrls = collectDocsUrls(ctx)
  const maxSteps = isReenrich ? REENRICH_MAX_STEPS : INITIAL_MAX_STEPS

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} starting (${isReenrich ? 're-enrich' : 'initial'})`)

  // Build tools: merge local tools with Exa MCP search tools
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
    console.log(`[enrichment] ${ctx.hostname}/${pagePath} exa tools loaded`)
  } catch (e) {
    console.error(`[enrichment] ${ctx.hostname}/${pagePath} exa MCP connection failed:`, e)
  }

  try {
    const result = await generateText({
      model,
      stopWhen: stepCountIs(maxSteps),
      system: isReenrich ? buildReenrichSystemPrompt(ctx) : buildSystemPrompt(ctx),
      prompt: isReenrich
        ? buildReenrichmentPrompt(pagePath, page.content, docsUrls)
        : buildEnrichmentPrompt(pagePath, page.content, docsUrls),
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
    if (mcpClient) {
      await mcpClient.close()
    }
  }
}

const GENERATE_SITEMAP_MAX_STEPS = 5

/**
 * Generate a sitemap from web docs when no spec was found.
 * Uses LLM + Exa search to discover API resources and operations from documentation.
 */
export async function generateSitemapFromWeb(ctx: PipelineContext) {
  const model = createModel(ctx)
  if (!model) return

  const docsUrls = collectDocsUrls(ctx)

  const system = `You are generating an API sitemap for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

No OpenAPI or GraphQL spec was found. Your job is to:
1. Search the web for official API documentation
2. Identify the main API resources (e.g., Users, Issues, Projects)
3. For each resource, identify operations (method, path, summary)
4. Call write_doc_page to create structured pages

Create a resources page at "sitemap/resources.json":
{
  "level": 1,
  "resources": [
    { "name": "Resource Name", "slug": "resource-name", "description": "Brief description", "common_operations": [{ "method": "GET", "path": "/resource", "summary": "List resources" }] }
  ]
}

Then for each resource, write a detail page at "sitemap/{slug}.json":
{
  "level": 2,
  "resource": "Resource Name",
  "description": "Description",
  "operations": [
    { "method": "GET", "path": "/resource", "summary": "List", "slug": "list-resources", "docs_url": "https://..." }
  ]
}

Also update the index page at "sitemap/index.json" with a description.

ONLY include operations you find in official documentation. Do NOT hallucinate endpoints.
Be conservative — it is better to have fewer accurate resources than many inaccurate ones.`

  let prompt = `Generate a sitemap for ${ctx.hostname}.`
  if (docsUrls.length > 0) {
    prompt += `\n\nKnown documentation sources:\n${docsUrls.map(u => `- ${u}`).join('\n')}`
  }
  prompt += `\n\nSearch for "${ctx.hostname} API documentation" to find official docs, then call write_doc_page for each page.`

  console.log(`[enrichment] generating sitemap from web docs for ${ctx.hostname}`)

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
    console.error(`[enrichment] exa MCP connection failed for sitemap generation:`, e)
  }

  try {
    const result = await generateText({
      model,
      stopWhen: stepCountIs(GENERATE_SITEMAP_MAX_STEPS),
      system,
      prompt,
      tools,
      onStepFinish: ({ toolCalls }) => {
        if (toolCalls?.length) {
          for (const tc of toolCalls) {
            console.log(`[enrichment] ${ctx.hostname} generate-sitemap tool_use: ${tc.toolName}`)
          }
        }
      },
    })

    console.log(`[enrichment] sitemap generation for ${ctx.hostname} done (${result.steps.length} steps)`)
  } finally {
    if (mcpClient) await mcpClient.close()
  }
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
