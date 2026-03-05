import type { Database } from '../db/index'
import type { Logger } from '../lib/logger'

/** Core environment — runs locally without WorkOS or Cloudflare. */
export interface CoreEnv {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
  ENCRYPTION_KEY: string
  DATABASE_URL?: string
}

export interface ManagementRights {
  rights: string[]
  vaultAdminSlugs: string[]
}

export interface CoreHonoEnv {
  Bindings: CoreEnv
  Variables: {
    db: Database
    managementRights?: ManagementRights
    token?: string
    orgId?: string
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
