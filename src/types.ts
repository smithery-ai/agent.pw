import type { Database } from './db/index'
import type { Redis } from '@upstash/redis'
import type { Logger } from './lib/logger'

export interface Hyperdrive {
  connectionString: string
}

export interface Env {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
  ENCRYPTION_KEY: string
  ANTHROPIC_API_KEY?: string
  ANTHROPIC_BASE_URL?: string
  AWS_ACCESS_KEY_ID?: string
  AWS_SECRET_ACCESS_KEY?: string
  AWS_REGION?: string
  WORKOS_CLIENT_ID: string
  WORKOS_API_KEY: string
  WORKOS_COOKIE_PASSWORD: string
  KV_REST_API_URL: string
  KV_REST_API_TOKEN: string
  BETTERSTACK_SOURCE_TOKEN?: string
  HYPERDRIVE?: Hyperdrive
  DISCOVERY_WORKFLOW?: Workflow
}

export interface ManagementRights {
  rights: string[]
  vaultAdminSlugs: string[]
}

export interface HonoEnv {
  Bindings: Env
  Variables: {
    db: Database
    redis: Redis
    managementRights?: ManagementRights
    token?: string
    session?: import('./lib/session').Session
    logger: Logger
    flushLogger: () => Promise<void>
  }
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface ProxyConstraint {
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  metadata?: Record<string, string>
  vault?: string
  ttl?: string | number
}
