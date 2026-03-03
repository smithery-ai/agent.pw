import type { Database } from './db/index'

export interface Env {
  BISCUIT_PRIVATE_KEY: string
  BASE_URL: string
}

export interface ManagementRights {
  rights: string[]
  vaultAdminSlugs: string[]
}

export interface HonoEnv {
  Bindings: Env
  Variables: {
    db: Database
    managementRights?: ManagementRights
    token?: string
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
