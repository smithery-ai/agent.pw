import type { InferSelectModel } from 'drizzle-orm'
import type { services } from '../db/schema'
import type { Database } from '../db/index'

export type ServiceRow = InferSelectModel<typeof services>

// ─── Pipeline Context ─────────────────────────────────────────────────────────

export interface PipelineContext {
  db: Database
  hostname: string
  service: ServiceRow
  bedrockToken?: string
  baseUrl: string
  /** Cloudflare Workflow binding for durable discovery execution */
  workflow?: Workflow
}

// ─── Probe Result (Phase 1) ──────────────────────────────────────────────────

export interface ProbeResult {
  apiType: 'rest' | 'graphql' | 'unknown'
  specUrl?: string
  specContent?: string
  graphqlSchema?: string
  docsUrl?: string
  authDetected: string[]
}

// ─── Doc Page Content Shapes ─────────────────────────────────────────────────

/** L0: Service root — what is this API, how to auth, quick start */
export interface DocIndexPage {
  level: 0
  service: string
  hostname: string
  api_type: 'rest' | 'graphql' | 'unknown'
  base_url: string
  description: string
  auth: { type: string; setup_url: string }[]
  quick_start?: {
    method: string
    path: string
    description: string
    example_response?: unknown
  }
  docs_url?: string
}

/** L1: Resource catalog — main objects and common operations */
export interface DocResourcesPage {
  level: 1
  resources: {
    name: string
    slug: string
    description: string
    common_operations: {
      method: string
      path: string
      summary: string
    }[]
  }[]
}

/** L2: Resource detail — all operations for one resource */
export interface DocResourceDetailPage {
  level: 2
  resource: string
  description: string
  operations: {
    method: string
    path: string
    summary: string
    slug: string
    parameters?: { name: string; type: string; required: boolean; description: string }[]
    example_request?: unknown
    example_response?: unknown
  }[]
}

/** L3: Operation detail — full field reference for one operation */
export interface DocOperationDetailPage {
  level: 3
  resource: string
  operation: string
  method: string
  path: string
  description: string
  parameters: { name: string; type: string; required: boolean; description: string }[]
  request_body?: { content_type: string; schema: unknown; example: unknown }
  responses: { status: number; description: string; example?: unknown }[]
  notes?: string
}

/** Generation metadata per hostname */
export interface DocMeta {
  hostname: string
  sources: string[]
  api_type: 'rest' | 'graphql' | 'unknown'
  coverage: {
    total_resources: number
    enriched_resources: number
    total_operations: number
    enriched_operations: number
  }
  pipeline_state: 'idle' | 'probing' | 'parsing' | 'enriching'
  last_full_run?: string
  staleness: {
    stale_pages: number
    oldest_page?: string
  }
}

export type DocPage = DocIndexPage | DocResourcesPage | DocResourceDetailPage | DocOperationDetailPage
export type PageStatus = 'skeleton' | 'enriched' | 'stale'
