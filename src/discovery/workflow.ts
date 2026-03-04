import { WorkflowEntrypoint, type WorkflowStep } from 'cloudflare:workers'
import type { WorkflowEvent } from 'cloudflare:workers'
import type { Env } from '../types'
import type { ProbeResult } from './types'
import { createDb } from '../db/index'
import { getService, listEnrichablePages } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { enrichPages } from './enrichment'

interface WorkflowParams {
  hostname: string
}

export class DiscoveryWorkflow extends WorkflowEntrypoint<Env, WorkflowParams> {
  async run(event: WorkflowEvent<WorkflowParams>, step: WorkflowStep) {
    const { hostname } = event.payload
    const connectionString = this.env.HYPERDRIVE?.connectionString
    if (!connectionString) throw new Error('HYPERDRIVE binding not configured')

    // Step 1: Look up service from DB (fail fast if missing)
    const service = await step.do('lookup-service', async () => {
      const db = createDb(connectionString)
      const svc = await getService(db, hostname)
      if (!svc) throw new Error(`Service not found: ${hostname}`)
      return svc
    })

    // Step 2: Probe the service (including external docs URLs)
    const probe = await step.do(
      'probe',
      { retries: { limit: 2, delay: '5 seconds', backoff: 'linear' } },
      async () => {
        console.log(`[discovery] probing ${hostname} (baseUrl: ${service.baseUrl})`)
        const result = await probeService(service.baseUrl, service.apiType ?? undefined, hostname)
        console.log(`[discovery] probe complete for ${hostname}: type=${result.apiType}, spec=${!!result.specContent}, graphql=${!!result.graphqlSchema}, docsUrl=${result.docsUrl ?? 'none'}, externalDocs=${result.externalDocsUrls.length}`)
        return result
      },
    )

    // Step 3: Deterministic discovery
    const pagePaths = await step.do('deterministic', async () => {
      const db = createDb(connectionString)
      const ctx = {
        db,
        hostname,
        service,
        anthropicApiKey: this.env.ANTHROPIC_API_KEY,
        awsAccessKeyId: this.env.AWS_ACCESS_KEY_ID,
        awsSecretAccessKey: this.env.AWS_SECRET_ACCESS_KEY,
        awsRegion: this.env.AWS_REGION,
        baseUrl: this.env.BASE_URL,
      }
      const result = await runDeterministicDiscovery(ctx, probe as ProbeResult)
      console.log(`[discovery] deterministic complete for ${hostname}: ${result.pagesWritten} pages, ${result.resourcesFound.length} resources, hasSpec=${result.hasSpec}`)

      // Return all enrichable page paths (skeleton + already enriched for re-enrichment)
      const db2 = createDb(connectionString)
      const enrichable = await listEnrichablePages(db2, hostname)
      const sorted = enrichable.sort((a, b) => {
        const depthA = a.path.split('/').length
        const depthB = b.path.split('/').length
        return depthA - depthB
      })
      return sorted.map(p => p.path)
    })

    // Step 4: Enrich each page individually (skeletons and re-enrichment of existing pages)
    const hasLlmProvider = this.env.AWS_ACCESS_KEY_ID || this.env.ANTHROPIC_API_KEY
    if (!hasLlmProvider) {
      console.log(`[discovery] skipping enrichment for ${hostname}: no LLM provider configured`)
      return
    }

    if (pagePaths.length === 0) {
      console.log(`[discovery] no pages to enrich for ${hostname}`)
      return
    }

    const probeResult = probe as ProbeResult
    console.log(`[discovery] enriching ${pagePaths.length} pages for ${hostname}`)

    for (const path of pagePaths) {
      await step.do(
        `enrich-${path}`,
        { retries: { limit: 2, delay: '10 seconds' } },
        async () => {
          const db = createDb(connectionString)
          const ctx = {
            db,
            hostname,
            service,
            anthropicApiKey: this.env.ANTHROPIC_API_KEY,
            awsAccessKeyId: this.env.AWS_ACCESS_KEY_ID,
            awsSecretAccessKey: this.env.AWS_SECRET_ACCESS_KEY,
            awsRegion: this.env.AWS_REGION,
            exaApiKey: this.env.EXA_API_KEY,
            baseUrl: this.env.BASE_URL,
            externalDocsUrls: probeResult.externalDocsUrls,
          }
          await enrichPages(ctx, [path])
        },
      )
    }
  }
}
