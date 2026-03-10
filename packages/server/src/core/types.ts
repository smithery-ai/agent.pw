import type { Database } from '../db/index'
import type { Logger } from '../lib/logger'

/** Core environment — runs locally without WorkOS or Cloudflare. */
export interface CoreEnv {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
  CLI_AUTH_BASE_URL?: string
  ENCRYPTION_KEY: string
  DATABASE_URL?: string
}

export interface TokenFacts {
  rights: string[]
  userId: string | null
  orgId: string | null
  path: string | null
  scopes: string[]
}

export interface CoreHonoEnv {
  Bindings: CoreEnv
  Variables: {
    db: Database
    tokenFacts?: TokenFacts
    token?: string
    userId?: string
    logger: Logger
    /** Optional filter applied to credential candidates during proxy resolution. */
    credentialFilter?: (cred: { path: string }) => boolean
  }
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface TokenConstraint {
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  ttl?: string | number
}
