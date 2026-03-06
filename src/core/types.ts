import type { Database } from '../db/index'
import type { Logger } from '../lib/logger'

/** Core environment — runs locally without WorkOS or Cloudflare. */
export interface CoreEnv {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
  ENCRYPTION_KEY: string
  DATABASE_URL?: string
}

export interface TokenFacts {
  rights: string[]
  userId: string | null
}

export interface CoreHonoEnv {
  Bindings: CoreEnv
  Variables: {
    db: Database
    tokenFacts?: TokenFacts
    token?: string
    userId?: string
    logger: Logger
  }
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface TokenConstraint {
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  ttl?: string | number
}
