import type { PipelineContext } from './types'
import { getDocPage, listDocPages, listSkeletonPages } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { enrichPages } from './enrichment'

// In-memory tracking to prevent duplicate runs per hostname
const activePipelines = new Map<string, Promise<void>>()
const activeEnrichments = new Map<string, Promise<void>>()

/**
 * Get a doc page, generating it if necessary.
 * - Cache hit (fresh): return immediately
 * - Cache hit (stale): return stale, queue background refresh
 * - Cache miss (other pages exist): generate on-demand (blocking)
 * - Cache miss (no pages): trigger full pipeline (blocking)
 */
export async function getOrGeneratePage(
  ctx: PipelineContext,
  path: string,
) {
  const existing = await getDocPage(ctx.db, ctx.hostname, path)

  if (existing && existing.status !== 'stale') {
    return existing
  }

  if (existing && existing.status === 'stale') {
    // Serve stale, queue background re-generation
    queueBackgroundEnrichment(ctx)
    return existing
  }

  // Check if any pages exist for this hostname
  const anyPages = await listDocPages(ctx.db, ctx.hostname)

  if (anyPages.length === 0) {
    // No pages at all: trigger full pipeline
    await triggerFullPipeline(ctx)
    return await getDocPage(ctx.db, ctx.hostname, path)
  }

  // Pages exist but this one doesn't.
  // For index and resources, they should have been created by the pipeline.
  // For other pages, try enrichment on demand.
  if (path === 'docs/index.json' || path === 'docs/resources.json') {
    // These should exist after pipeline, something went wrong
    await triggerFullPipeline(ctx)
    return await getDocPage(ctx.db, ctx.hostname, path)
  }

  // For L2/L3 pages, the skeleton might not exist yet — return null
  // The enrichment pipeline will create them in the background
  queueBackgroundEnrichment(ctx)
  return null
}

/**
 * Run the full pipeline: probe → deterministic discovery → queue enrichment.
 * Idempotent: concurrent calls for the same hostname share one pipeline run.
 */
export function triggerFullPipeline(ctx: PipelineContext): Promise<void> {
  const key = ctx.hostname
  const existing = activePipelines.get(key)
  if (existing) {
    console.log(`[discovery] pipeline already running for ${key}, joining existing run`)
    return existing
  }

  const pipeline = runFullPipeline(ctx)
    .finally(() => activePipelines.delete(key))

  activePipelines.set(key, pipeline)
  return pipeline
}

async function runFullPipeline(ctx: PipelineContext) {
  console.log(`[discovery] pipeline started for ${ctx.hostname} (baseUrl: ${ctx.service.baseUrl})`)

  // Phase 1: Probe
  const probe = await probeService(ctx.service.baseUrl, ctx.service.apiType ?? undefined)
  console.log(`[discovery] probe complete for ${ctx.hostname}: type=${probe.apiType}, spec=${!!probe.specContent}, graphql=${!!probe.graphqlSchema}, docsUrl=${probe.docsUrl ?? 'none'}`)

  // Phase 2: Deterministic discovery
  const result = await runDeterministicDiscovery(ctx, probe)
  console.log(`[discovery] deterministic complete for ${ctx.hostname}: ${result.pagesWritten} pages, ${result.resourcesFound.length} resources, hasSpec=${result.hasSpec}`)

  // Phase 3: Queue enrichment in background
  queueBackgroundEnrichment(ctx)
}

/**
 * Queue background enrichment for skeleton pages.
 * Idempotent: only one enrichment job per hostname runs at a time.
 */
function queueBackgroundEnrichment(ctx: PipelineContext) {
  const key = ctx.hostname
  if (activeEnrichments.has(key)) return

  const job = runBackgroundEnrichment(ctx)
    .catch(err => console.error(`[discovery] background enrichment failed for ${key}:`, err))
    .finally(() => activeEnrichments.delete(key))

  activeEnrichments.set(key, job)
}

async function runBackgroundEnrichment(ctx: PipelineContext) {
  if (!ctx.bedrockApiKey) {
    console.log(`[discovery] skipping enrichment for ${ctx.hostname}: no BEDROCK_API_KEY configured`)
    return
  }

  const skeletons = await listSkeletonPages(ctx.db, ctx.hostname)
  if (skeletons.length === 0) {
    console.log(`[discovery] no skeleton pages to enrich for ${ctx.hostname}`)
    return
  }
  console.log(`[discovery] enriching ${skeletons.length} skeleton pages for ${ctx.hostname}`)

  // BFS order: sort by level (derived from path depth)
  const sorted = skeletons.sort((a, b) => {
    const depthA = a.path.split('/').length
    const depthB = b.path.split('/').length
    return depthA - depthB
  })

  const paths = sorted.map(p => p.path)
  await enrichPages(ctx, paths)
}
