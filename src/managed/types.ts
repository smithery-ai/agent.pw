import type { Database } from '../db/index'
import type { Logger } from '../lib/logger'

export interface Hyperdrive {
  connectionString: string
}

/** Full managed environment — extends core with WorkOS and Cloudflare bindings. */
export interface Env {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
  ENCRYPTION_KEY: string
  WORKOS_CLIENT_ID?: string
  WORKOS_API_KEY?: string
  WORKOS_COOKIE_PASSWORD?: string
  OTEL_EXPORTER_OTLP_ENDPOINT?: string
  OTEL_EXPORTER_OTLP_HEADERS?: string
  HYPERDRIVE?: Hyperdrive
}

export interface HonoEnv {
  Bindings: Env
  Variables: {
    db: Database
    tokenFacts?: import('../core/types').TokenFacts
    token?: string
    userId?: string
    session?: import('./session').Session
    logger: Logger
  }
}
