import { WorkflowEntrypoint, type WorkflowStep } from 'cloudflare:workers'
import type { WorkflowEvent } from 'cloudflare:workers'
import type { Env } from '../types'
import { createDb } from '../db/index'
import { getService, listEnrichablePages, getAnyCredentialForService } from '../db/queries'
import { probeService } from './probe'
import { runDeterministicDiscovery } from './deterministic'
import { enrichPages, generateSitemapFromWeb } from './enrichment'
import { decryptCredentials } from '../lib/credentials-crypto'

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

    // Step 3: If no spec found, try LLM-powered sitemap generation from web docs
    if (!discoveryResult.hasSpec && hasLlmProvider) {
      await step.do(
        'generate-sitemap',
        { retries: { limit: 1, delay: '10 seconds' } },
        async () => {
          console.log(`[discovery] no spec found for ${hostname}, generating sitemap from web docs`)
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
          await generateSitemapFromWeb(ctx)
        },
      )
    }

    // Step 4: List enrichable pages
    const pagePaths = await step.do('list-enrichable', async () => {
      const db = createDb(connectionString)
      const enrichable = await listEnrichablePages(db, hostname)
      const sorted = enrichable.sort((a, b) => {
        const depthA = a.path.split('/').length
        const depthB = b.path.split('/').length
        return depthA - depthB
      })
      return sorted.map(p => p.path)
    })

    // Step 6: Enrich each page individually (skeletons and re-enrichment of existing pages)
    if (!hasLlmProvider) {
      console.log(`[discovery] skipping enrichment for ${hostname}: no LLM provider configured`)
      return
    }

    if (pagePaths.length === 0) {
      console.log(`[discovery] no pages to enrich for ${hostname}`)
      return
    }

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
            baseUrl: this.env.BASE_URL,
            externalDocsUrls: discoveryResult.externalDocsUrls,
          }
          await enrichPages(ctx, [path])
        },
      )
    }
  }
}
