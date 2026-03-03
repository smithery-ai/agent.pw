import AnthropicBedrock from '@anthropic-ai/bedrock-sdk'
import type { Tool, MessageParam, ToolResultBlockParam } from '@anthropic-ai/sdk/resources/messages/messages'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage, listDocPages } from '../db/queries'

const ENRICHMENT_MODEL = 'us.anthropic.claude-sonnet-4-6-20250514-v1:0'
const MAX_TURNS = 10

const tools: Tool[] = [
  {
    name: 'fetch_upstream',
    description:
      'Fetch a URL. Use this to read API documentation pages, probe endpoints, or fetch example responses from the upstream service.',
    input_schema: {
      type: 'object' as const,
      properties: {
        url: { type: 'string', description: 'Full URL to fetch' },
        method: { type: 'string', enum: ['GET', 'POST'], description: 'HTTP method (default GET)' },
        body: { type: 'string', description: 'Request body for POST requests' },
      },
      required: ['url'],
    },
  },
  {
    name: 'write_doc_page',
    description:
      'Write an enriched documentation page. The content should be a structured JSON object matching the doc page schema.',
    input_schema: {
      type: 'object' as const,
      properties: {
        path: { type: 'string', description: 'Page path, e.g. "docs/issues.json"' },
        content: {
          type: 'object',
          description: 'The page content object (will be JSON-stringified and stored)',
        },
      },
      required: ['path', 'content'],
    },
  },
]

function buildSystemPrompt(ctx: PipelineContext) {
  return `You are a technical writer generating API documentation for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

Guidelines:
- Write concise, developer-friendly descriptions
- Generate realistic example requests and responses with placeholder IDs
- For resources: identify the 3-5 most common operations
- For operations: include required parameters and at least one example
- Do NOT hallucinate endpoints or fields that don't exist
- Use the fetch_upstream tool to read docs if you need more information
- Use the write_doc_page tool to save your enriched page
- Mark content as best-effort if unsure — a partial page is better than nothing`
}

function buildEnrichmentPrompt(
  pagePath: string,
  pageContent: string,
  existingPages: { path: string; content: string }[],
  docsUrl?: string,
) {
  let prompt = `Enrich the following skeleton documentation page. The current content is minimal — add descriptions, examples, and details.

Page to enrich: ${pagePath}
Current content:
${pageContent}

`

  if (existingPages.length > 0) {
    prompt += `Context from other generated pages:\n`
    for (const p of existingPages.slice(0, 5)) {
      prompt += `--- ${p.path} ---\n${p.content.slice(0, 500)}\n\n`
    }
  }

  if (docsUrl) {
    prompt += `\nThe API has documentation at ${docsUrl} — you can fetch it for reference.\n`
  }

  prompt += `\nUse the write_doc_page tool to save your enriched version of "${pagePath}".`

  return prompt
}

async function executeTool(
  ctx: PipelineContext,
  toolName: string,
  input: Record<string, unknown>,
): Promise<string> {
  if (toolName === 'fetch_upstream') {
    const url = input.url as string
    const method = (input.method as string) ?? 'GET'
    const body = input.body as string | undefined

    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5000)
      const res = await fetch(url, {
        method,
        body,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        signal: controller.signal,
      })
      clearTimeout(timer)

      const text = await res.text()
      return text.length > 10000 ? `${text.slice(0, 10000)}\n... (truncated)` : text
    } catch (e) {
      return `Error fetching ${url}: ${e instanceof Error ? e.message : String(e)}`
    }
  }

  if (toolName === 'write_doc_page') {
    const path = input.path as string
    const content = input.content as Record<string, unknown>

    await upsertDocPage(ctx.db, ctx.hostname, path, JSON.stringify(content), 'enriched')
    return `Page written: ${path}`
  }

  return `Unknown tool: ${toolName}`
}

export async function enrichPage(ctx: PipelineContext, pagePath: string) {
  if (!ctx.awsRegion) {
    return // Skip enrichment without AWS config
  }

  const page = await getDocPage(ctx.db, ctx.hostname, pagePath)
  if (!page || !page.content) return

  const existingPages = await listDocPages(ctx.db, ctx.hostname)
  const otherPages = existingPages
    .filter(p => p.path !== pagePath && p.content)
    .map(p => ({ path: p.path, content: p.content! }))

  const client = new AnthropicBedrock({ awsRegion: ctx.awsRegion })

  const messages: MessageParam[] = [
    {
      role: 'user',
      content: buildEnrichmentPrompt(
        pagePath,
        page.content,
        otherPages,
        ctx.service.docsUrl ?? undefined,
      ),
    },
  ]

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const response = await client.messages.create({
      model: ENRICHMENT_MODEL,
      max_tokens: 4096,
      system: buildSystemPrompt(ctx),
      tools,
      messages,
    })

    if (response.stop_reason === 'tool_use') {
      const toolResults: ToolResultBlockParam[] = []

      for (const block of response.content) {
        if (block.type === 'tool_use') {
          const result = await executeTool(ctx, block.name, block.input as Record<string, unknown>)
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: result })
        }
      }

      messages.push({ role: 'assistant', content: response.content })
      messages.push({ role: 'user', content: toolResults })
      continue
    }

    break
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
