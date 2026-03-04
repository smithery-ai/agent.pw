import { generateText, stepCountIs, tool } from 'ai'
import { createAmazonBedrock } from '@ai-sdk/amazon-bedrock'
import { createAnthropic } from '@ai-sdk/anthropic'
import { z } from 'zod'
import type { PipelineContext } from './types'
import { getDocPage, upsertDocPage, listDocPages } from '../db/queries'

const BEDROCK_MODEL = 'anthropic.claude-sonnet-4-6-20250514-v1:0'
const ANTHROPIC_MODEL = 'claude-sonnet-4-6'
const INITIAL_MAX_STEPS = 3
const REENRICH_MAX_STEPS = 5

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

function buildReenrichSystemPrompt(ctx: PipelineContext) {
  return `You are a technical writer improving existing API documentation for ${ctx.service.displayName ?? ctx.hostname} (${ctx.service.baseUrl}).

You are reviewing and improving documentation that was previously generated. Your job is to make it MORE accurate and useful, not to rewrite from scratch.

Guidelines:
- Improve descriptions to be more specific and helpful
- Add missing parameters, examples, or edge cases
- Fix any inaccurate information
- Fetch upstream documentation for reference to verify and improve content
- Do NOT remove existing accurate content — only add to it or correct errors
- Call write_doc_page when you have improvements ready`
}

function buildEnrichmentPrompt(
  pagePath: string,
  pageContent: string,
  existingPages: { path: string; content: string }[],
  docsUrls: string[],
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

  if (docsUrls.length > 0) {
    prompt += `\nAPI documentation sources you can fetch for reference:\n`
    for (const url of docsUrls) {
      prompt += `- ${url}\n`
    }
  }

  prompt += `\nUse the write_doc_page tool to save your enriched version of "${pagePath}".`

  return prompt
}

function buildReenrichmentPrompt(
  pagePath: string,
  pageContent: string,
  existingPages: { path: string; content: string }[],
  docsUrls: string[],
) {
  let prompt = `Review and improve this existing documentation page. It was previously generated and may have gaps or inaccuracies.

Page: ${pagePath}
Current content:
${pageContent}

`

  if (existingPages.length > 0) {
    prompt += `Context from other pages:\n`
    for (const p of existingPages.slice(0, 5)) {
      prompt += `--- ${p.path} ---\n${p.content.slice(0, 500)}\n\n`
    }
  }

  if (docsUrls.length > 0) {
    prompt += `\nAPI documentation sources — fetch these to verify and improve the content:\n`
    for (const url of docsUrls) {
      prompt += `- ${url}\n`
    }
    prompt += `\nFetch at least one documentation source before writing improvements.\n`
  }

  prompt += `\nCall write_doc_page with your improved version of "${pagePath}". If the page is already accurate and complete, write it back unchanged.`

  return prompt
}

function buildTools(ctx: PipelineContext) {
  return {
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

  const existingPages = await listDocPages(ctx.db, ctx.hostname)
  const otherPages = existingPages
    .filter(p => p.path !== pagePath && p.content)
    .map(p => ({ path: p.path, content: p.content! }))

  const docsUrls = collectDocsUrls(ctx)
  const maxSteps = isReenrich ? REENRICH_MAX_STEPS : INITIAL_MAX_STEPS

  console.log(`[enrichment] ${ctx.hostname}/${pagePath} starting (${isReenrich ? 're-enrich' : 'initial'})`)

  const result = await generateText({
    model,
    stopWhen: stepCountIs(maxSteps),
    system: isReenrich ? buildReenrichSystemPrompt(ctx) : buildSystemPrompt(ctx),
    prompt: isReenrich
      ? buildReenrichmentPrompt(pagePath, page.content, otherPages, docsUrls)
      : buildEnrichmentPrompt(pagePath, page.content, otherPages, docsUrls),
    tools: buildTools(ctx),
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
