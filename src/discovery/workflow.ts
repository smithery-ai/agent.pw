import { WorkflowEntrypoint, type WorkflowStep } from 'cloudflare:workers'
import type { WorkflowEvent } from 'cloudflare:workers'
import type { Env } from '../types'
import { createDb } from '../db/index'
import { getService, getAnyCredentialForService, updateCrawlState } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { runDiscoveryAgent } from './enrichment'
import { decryptCredentials } from '../lib/credentials-crypto'

interface WorkflowParams {
  hostname: string
}

export class DiscoveryWorkflow extends WorkflowEntrypoint<Env, WorkflowParams> {
  async run(event: WorkflowEvent<WorkflowParams>, step: WorkflowStep) {
    const { hostname } = event.payload
    const connectionString = this.env.HYPERDRIVE?.connectionString
    if (!connectionString) throw new Error('HYPERDRIVE binding not configured')

    // Step 1: Look up service and set crawl state to 'crawling'
    const service = await step.do('lookup-service', async () => {
      const db = createDb(connectionString)
      const svc = await getService(db, hostname)
      if (!svc) throw new Error(`Service not found: ${hostname}`)
      await updateCrawlState(db, hostname, 'crawling')
      return svc
    })

    try {
      // Step 2: Probe + deterministic discovery (combined to avoid storing large specs in workflow state)
      const discoveryResult = await step.do(
        'probe-and-discover',
        { retries: { limit: 2, delay: '5 seconds', backoff: 'linear' } },
        async () => {
          // Resolve auth headers for authenticated probing (e.g., GraphQL introspection)
          let authHeaders: Record<string, string> | undefined
          if (this.env.ENCRYPTION_KEY) {
            const db = createDb(connectionString)
            const cred = await getAnyCredentialForService(db, hostname)
            if (cred) {
              try {
                const stored = await decryptCredentials(this.env.ENCRYPTION_KEY, cred.encryptedCredentials)
                authHeaders = stored.headers
                console.log(`[discovery] using stored credentials for ${hostname} probe`)
              } catch {
                // Credential decryption failed — proceed without auth
              }
            }
          }

          // Probe the service
          console.log(`[discovery] probing ${hostname} (baseUrl: ${service.baseUrl})`)
          const probe = await probeService(
            service.baseUrl,
            service.apiType ?? undefined,
            hostname,
            { authHeaders },
          )
          console.log(`[discovery] probe complete for ${hostname}: type=${probe.apiType}, spec=${!!probe.specContent}, graphql=${!!probe.graphqlSchema}, docsUrl=${probe.docsUrl ?? 'none'}, externalDocs=${probe.externalDocsUrls.length}`)

          // Run deterministic discovery (consumes spec content in-memory, writes pages to DB)
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
          const result = await runDeterministicDiscovery(ctx, probe)
          console.log(`[discovery] deterministic complete for ${hostname}: ${result.pagesWritten} pages, ${result.resourcesFound.length} resources, hasSpec=${result.hasSpec}`)

          // Return only small metadata (not the full spec content)
          return { hasSpec: result.hasSpec, externalDocsUrls: probe.externalDocsUrls }
        },
      )

      const hasLlmProvider = this.env.AWS_ACCESS_KEY_ID || this.env.ANTHROPIC_API_KEY

      if (!hasLlmProvider) {
        console.log(`[discovery] skipping discovery agent for ${hostname}: no LLM provider configured`)
        const db = createDb(connectionString)
        await updateCrawlState(db, hostname, 'ready')
        return
      }

      // Step 3: Run discovery agent (Opus, 50 steps) — finds specs, crawls docs, enriches pages
      await step.do(
        'discovery-agent',
        { retries: { limit: 1, delay: '10 seconds' } },
        async () => {
          console.log(`[discovery] running discovery agent for ${hostname}`)
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
            externalDocsUrls: discoveryResult.externalDocsUrls,
          }
          await runDiscoveryAgent(ctx)
        },
      )

      // Mark as ready
      await step.do('mark-ready', async () => {
        const db = createDb(connectionString)
        await updateCrawlState(db, hostname, 'ready')
      })
    } catch (e) {
      // Mark as failed on any unrecoverable error
      try {
        const db = createDb(connectionString)
        await updateCrawlState(db, hostname, 'failed')
      } catch {
        // Best effort
      }
      throw e
    }
  }
}
