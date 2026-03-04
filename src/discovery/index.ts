import type { PipelineContext } from './types'
import { getDocPage, listDocPages, listSkeletonPages } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { enrichPages } from './enrichment'

/**
 * Get a doc page, generating it if necessary.
 * - Cache hit (fresh): return immediately
 * - Cache hit (stale): return stale, trigger workflow refresh
 * - Cache miss (other pages exist): trigger workflow, return null (caller returns 404)
 * - Cache miss (no pages): trigger workflow, return null
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
    // Serve stale, trigger workflow refresh in background
    triggerDiscoveryWorkflow(ctx)
    return existing
  }

  // Check if any pages exist for this hostname
  const anyPages = await listDocPages(ctx.db, ctx.hostname)

  if (anyPages.length === 0) {
    // No pages at all: trigger full pipeline via workflow
    await triggerDiscoveryWorkflow(ctx)
    return await getDocPage(ctx.db, ctx.hostname, path)
  }

  // Pages exist but this one doesn't.
  if (path === 'docs/index.json' || path === 'docs/resources.json') {
    // These should exist after pipeline, something went wrong
    await triggerDiscoveryWorkflow(ctx)
    return await getDocPage(ctx.db, ctx.hostname, path)
  }

  // For L2/L3 pages, trigger enrichment workflow
  triggerDiscoveryWorkflow(ctx)
  return null
}

/**
 * Trigger the discovery workflow for a hostname.
 * Uses Cloudflare Workflows when available, falls back to in-process execution.
 */
export async function triggerDiscoveryWorkflow(ctx: PipelineContext) {
  if (ctx.workflow) {
    const id = `discovery-${ctx.hostname}-${Date.now()}`
    console.log(`[discovery] triggering workflow for ${ctx.hostname} (instance: ${id})`)
    await ctx.workflow.create({ id, params: { hostname: ctx.hostname } })
    return id
  }

  // Fallback: run in-process (for local dev / tests without workflow binding)
  console.log(`[discovery] no workflow binding, running in-process for ${ctx.hostname}`)

  const probe = await probeService(ctx.service.baseUrl, ctx.service.apiType ?? undefined)
  await runDeterministicDiscovery(ctx, probe)

  if (ctx.anthropicApiKey) {
    const skeletons = await listSkeletonPages(ctx.db, ctx.hostname)
    const sorted = skeletons.sort((a, b) => a.path.split('/').length - b.path.split('/').length)
    await enrichPages(ctx, sorted.map(p => p.path))
  }
}
