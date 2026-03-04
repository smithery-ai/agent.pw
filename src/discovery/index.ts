import type { PipelineContext } from './types'
import { getDocPage, listDocPages, getAnyCredentialForService, updateCrawlState } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { runDiscoveryAgent } from './enrichment'
import { decryptCredentials } from '../lib/credentials-crypto'

const STALE_THRESHOLD_MS = 60 * 60 * 1000 // 1 hour

/**
 * Check if discovery should be re-triggered for a hostname.
 * Returns true if _meta.json is missing or older than 1 hour.
 */
export async function isDiscoveryStale(ctx: PipelineContext): Promise<boolean> {
  const docs = await listDocPages(ctx.db, ctx.hostname)
  if (docs.length === 0) return true

  const meta = await getDocPage(ctx.db, ctx.hostname, '_meta.json')
  if (!meta) return true

  const age = Date.now() - new Date(meta.generatedAt).getTime()
  return age > STALE_THRESHOLD_MS
}

/**
 * Get a doc page, generating it if necessary.
 * - Cache hit (fresh): return immediately, but check if discovery should re-run
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
    // Page is fresh, but check if discovery pipeline should re-run
    maybeRetriggerDiscovery(ctx)
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
    // No pages at all: trigger discovery in background, return null (caller returns 404)
    triggerDiscoveryWorkflow(ctx)
    return null
  }

  // Pages exist but this one doesn't — trigger discovery in background
  triggerDiscoveryWorkflow(ctx)
  return null
}

/**
 * Check staleness and re-trigger discovery in the background if needed.
 * Non-blocking — fires and forgets.
 */
async function maybeRetriggerDiscovery(ctx: PipelineContext) {
  try {
    const stale = await isDiscoveryStale(ctx)
    if (stale) {
      console.log(`[discovery] re-triggering for ${ctx.hostname} (stale >1h)`)
      triggerDiscoveryWorkflow(ctx)
    }
  } catch (e) {
    console.error(`[discovery] staleness check failed for ${ctx.hostname}:`, e)
  }
}

/**
 * Trigger the discovery workflow for a hostname.
 * Uses Cloudflare Workflows when available, falls back to in-process execution.
 */
export async function triggerDiscoveryWorkflow(ctx: PipelineContext) {
  if (ctx.workflow) {
    const id = `discovery-${ctx.hostname.replaceAll('.', '_')}-${Date.now()}`
    console.log(`[discovery] triggering workflow for ${ctx.hostname} (instance: ${id})`)
    await ctx.workflow.create({ id, params: { hostname: ctx.hostname } })
    return id
  }

  // Fallback: run in-process (for local dev / tests without workflow binding)
  console.log(`[discovery] no workflow binding, running in-process for ${ctx.hostname}`)

  try {
    await updateCrawlState(ctx.db, ctx.hostname, 'crawling')

    // Try to resolve auth headers for authenticated probing (e.g., GraphQL introspection)
    let authHeaders: Record<string, string> | undefined
    if (ctx.encryptionKey) {
      try {
        const cred = await getAnyCredentialForService(ctx.db, ctx.hostname)
        if (cred) {
          const stored = await decryptCredentials(ctx.encryptionKey, cred.encryptedCredentials)
          authHeaders = stored.headers
          console.log(`[discovery] using stored credentials for ${ctx.hostname} probe`)
        }
      } catch {
        // Credential decryption failed — proceed without auth
      }
    }

    const probe = await probeService(ctx.service.baseUrl, ctx.service.apiType ?? undefined, ctx.hostname, { authHeaders })
    await runDeterministicDiscovery(ctx, probe)

    const hasLlmProvider = ctx.awsAccessKeyId || ctx.anthropicApiKey
    if (hasLlmProvider) {
      await runDiscoveryAgent({ ...ctx, externalDocsUrls: probe.externalDocsUrls })
    }

    await updateCrawlState(ctx.db, ctx.hostname, 'ready')
  } catch (e) {
    console.error(`[discovery] in-process discovery failed for ${ctx.hostname}:`, e)
    try {
      await updateCrawlState(ctx.db, ctx.hostname, 'failed')
    } catch {
      // Best effort
    }
  }
}
