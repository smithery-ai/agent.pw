import { query, tool, createSdkMcpServer, type McpServerConfig, type SDKUserMessage } from '@anthropic-ai/claude-agent-sdk'
import { z } from 'zod'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage, listDocPages } from '../db/queries'

const MAX_TURNS = 3

function buildSystemPrompt(ctx: PipelineContext) {
  return `You are a technical writer generating API documentation for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

IMPORTANT: Call write_doc_page IMMEDIATELY with your best effort. Do NOT fetch more than one URL before writing. A partial page NOW is better than a perfect page later.

You have access to web search via the Exa MCP — use it to find official API documentation, guides, or examples when the upstream URL alone is insufficient.

Guidelines:
- Write concise, developer-friendly descriptions
- Generate realistic example requests and responses with placeholder IDs
- For resources: identify the 3-5 most common operations
- For operations: include required parameters and at least one example
- Do NOT hallucinate endpoints or fields that don't exist
- You may search the web or fetch ONE upstream URL if you need more context, then WRITE immediately
- Mark content as best-effort if unsure — a partial page is better than nothing`
}

function buildEnrichmentPrompt(
  pagePath: string,
  pageContent: string,
  existingPages: { path: string; content: string }[],
  docsUrl?: string,
) {
  let prompt = `Enrich this skeleton doc page by adding descriptions and examples, then IMMEDIATELY call write_doc_page to save it.

Page: ${pagePath}
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

function createEnrichmentServer(ctx: PipelineContext) {
  const fetchUpstream = tool(
    'fetch_upstream',
    'Fetch a URL. Use this to read API documentation pages, probe endpoints, or fetch example responses from the upstream service.',
    {
      url: z.string().describe('Full URL to fetch'),
      method: z.enum(['GET', 'POST']).optional().describe('HTTP method (default GET)'),
      body: z.string().optional().describe('Request body for POST requests'),
    },
    async (args) => {
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 5000)
        const res = await fetch(args.url, {
          method: args.method ?? 'GET',
          body: args.body,
          headers: args.body ? { 'Content-Type': 'application/json' } : undefined,
          signal: controller.signal,
        })
        clearTimeout(timer)
        const text = await res.text()
        const truncated = text.length > 10000 ? `${text.slice(0, 10000)}\n... (truncated)` : text
        return { content: [{ type: 'text' as const, text: truncated }] }
      } catch (e) {
        return { content: [{ type: 'text' as const, text: `Error fetching ${args.url}: ${e instanceof Error ? e.message : String(e)}` }] }
      }
    },
  )

  const writeDocPage = tool(
    'write_doc_page',
    'Write an enriched documentation page. The content should be a structured JSON object matching the doc page schema.',
    {
      path: z.string().describe('Page path, e.g. "docs/issues.json"'),
      content: z.record(z.string(), z.unknown()).describe('The page content object (will be JSON-stringified and stored)'),
    },
    async (args) => {
      await upsertDocPage(ctx.db, ctx.hostname, args.path, JSON.stringify(args.content), 'enriched')
      return { content: [{ type: 'text' as const, text: `Page written: ${args.path}` }] }
    },
  )

  return createSdkMcpServer({
    name: 'warden',
    version: '1.0.0',
    tools: [fetchUpstream, writeDocPage],
  })
}

export async function enrichPage(ctx: PipelineContext, pagePath: string) {
  if (!ctx.bedrockToken) return

  const page = await getDocPage(ctx.db, ctx.hostname, pagePath)
  if (!page || !page.content) return

  const existingPages = await listDocPages(ctx.db, ctx.hostname)
  const otherPages = existingPages
    .filter(p => p.path !== pagePath && p.content)
    .map(p => ({ path: p.path, content: p.content! }))

  const customServer = createEnrichmentServer(ctx)

  const mcpServers: Record<string, McpServerConfig> = {
    warden: customServer,
    exa: { type: 'http', url: 'https://mcp.exa.ai/mcp' },
  }

  const prompt = buildEnrichmentPrompt(
    pagePath,
    page.content,
    otherPages,
    ctx.service.docsUrl ?? undefined,
  )

  async function* generateMessages(): AsyncGenerator<SDKUserMessage> {
    yield {
      type: 'user',
      message: { role: 'user', content: prompt },
      parent_tool_use_id: null,
      session_id: '',
    }
  }

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} starting`)

  for await (const message of query({
    prompt: generateMessages(),
    options: {
      systemPrompt: buildSystemPrompt(ctx),
      maxTurns: MAX_TURNS,
      mcpServers,
      allowedTools: ['mcp__warden__*', 'mcp__exa__*'],
      permissionMode: 'bypassPermissions',
      allowDangerouslySkipPermissions: true,
      env: {
        CLAUDE_CODE_USE_BEDROCK: '1',
        AWS_BEARER_TOKEN_BEDROCK: ctx.bedrockToken,
        AWS_REGION: 'us-east-1',
        ANTHROPIC_MODEL: 'us.anthropic.claude-sonnet-4-6',
      },
    },
  })) {
    if (message.type === 'result') {
      if (message.subtype === 'success') {
        console.log(`[enrichment] ${ctx.hostname}/${pagePath} completed (turns=${message.num_turns})`)
      } else {
        console.error(`[enrichment] ${ctx.hostname}/${pagePath} error: ${message.subtype}`)
      }
    }
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
