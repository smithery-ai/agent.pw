import type { PipelineContext } from './types'
import { getDocPage, listDocPages, listSkeletonPages } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { enrichPages } from './enrichment'

// In-memory tracking to prevent duplicate background runs
const activeJobs = new Map<string, Promise<void>>()

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
 * Run the full pipeline: probe → deterministic discovery → queue enrichment
 */
export async function triggerFullPipeline(ctx: PipelineContext) {
  // Phase 1: Probe
  const probe = await probeService(ctx.service.baseUrl, ctx.service.apiType ?? undefined)

  // Phase 2: Deterministic discovery
  await runDeterministicDiscovery(ctx, probe)

  // Phase 3: Queue enrichment in background
  queueBackgroundEnrichment(ctx)
}

/**
 * Queue background enrichment for skeleton pages.
 * Deduplicates: only one enrichment job per hostname runs at a time.
 */
function queueBackgroundEnrichment(ctx: PipelineContext) {
  const key = ctx.hostname
  if (activeJobs.has(key)) return

  const job = runBackgroundEnrichment(ctx)
    .catch(err => console.error(`[discovery] background enrichment failed for ${key}:`, err))
    .finally(() => activeJobs.delete(key))

  activeJobs.set(key, job)
}

async function runBackgroundEnrichment(ctx: PipelineContext) {
  if (!ctx.awsRegion) return

  const skeletons = await listSkeletonPages(ctx.db, ctx.hostname)
  if (skeletons.length === 0) return

  // BFS order: sort by level (derived from path depth)
  const sorted = skeletons.sort((a, b) => {
    const depthA = a.path.split('/').length
    const depthB = b.path.split('/').length
    return depthA - depthB
  })

  const paths = sorted.map(p => p.path)
  await enrichPages(ctx, paths)
}
