import { generateText, stepCountIs, tool } from 'ai'
import { createAnthropic } from '@ai-sdk/anthropic'
import { z } from 'zod'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage, listDocPages } from '../db/queries'

const ENRICHMENT_MODEL = 'claude-sonnet-4-6'
const MAX_STEPS = 3

function buildSystemPrompt(ctx: PipelineContext) {
  return `You are a technical writer generating API documentation for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

IMPORTANT: Call write_doc_page IMMEDIATELY with your best effort. Do NOT fetch more than one URL before writing. A partial page NOW is better than a perfect page later.

Guidelines:
- Write concise, developer-friendly descriptions
- Generate realistic example requests and responses with placeholder IDs
- For resources: identify the 3-5 most common operations
- For operations: include required parameters and at least one example
- Do NOT hallucinate endpoints or fields that don't exist
- You may fetch ONE upstream URL if you need more context, then WRITE immediately
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

export async function enrichPage(ctx: PipelineContext, pagePath: string) {
  if (!ctx.anthropicApiKey) return

  const page = await getDocPage(ctx.db, ctx.hostname, pagePath)
  if (!page || !page.content) return

  const existingPages = await listDocPages(ctx.db, ctx.hostname)
  const otherPages = existingPages
    .filter(p => p.path !== pagePath && p.content)
    .map(p => ({ path: p.path, content: p.content! }))

  const provider = createAnthropic({
    apiKey: ctx.anthropicApiKey,
    ...(ctx.anthropicBaseUrl && { baseURL: ctx.anthropicBaseUrl }),
  })

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} starting`)

  const result = await generateText({
    model: provider(ENRICHMENT_MODEL),
    stopWhen: stepCountIs(MAX_STEPS),
    system: buildSystemPrompt(ctx),
    prompt: buildEnrichmentPrompt(
      pagePath,
      page.content,
      otherPages,
      ctx.service.docsUrl ?? undefined,
    ),
    tools: {
      fetch_upstream: tool({
        description:
          'Fetch a URL. Use this to read API documentation pages, probe endpoints, or fetch example responses from the upstream service.',
        inputSchema: z.object({
          url: z.string().describe('Full URL to fetch'),
          method: z.enum(['GET', 'POST']).optional().describe('HTTP method (default GET)'),
          body: z.string().optional().describe('Request body for POST requests'),
        }),
        execute: async (input) => {
          const { url, method, body } = input
          try {
            const controller = new AbortController()
            const timer = setTimeout(() => controller.abort(), 5000)
            const res = await fetch(url, {
              method: method ?? 'GET',
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
        },
      }),
      write_doc_page: tool({
        description:
          'Write an enriched documentation page. The content should be a structured JSON object matching the doc page schema.',
        inputSchema: z.object({
          path: z.string().describe('Page path, e.g. "docs/issues.json"'),
          content: z.record(z.string(), z.unknown()).describe('The page content object (will be JSON-stringified and stored)'),
        }),
        execute: async (input) => {
          await upsertDocPage(ctx.db, ctx.hostname, input.path, JSON.stringify(input.content), 'enriched')
          return `Page written: ${input.path}`
        },
      }),
    },
    onStepFinish: ({ toolCalls }) => {
      if (toolCalls?.length) {
        for (const tc of toolCalls) {
          console.log(`[enrichment] ${ctx.hostname}/${pagePath} tool_use: ${tc.toolName}`)
        }
      }
    },
  })

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} done (${result.steps.length} steps)`)
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
