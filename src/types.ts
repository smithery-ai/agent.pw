export interface Env {
  DB: D1Database
  ADMIN_KEY: string
  ENCRYPTION_KEY: string
  BISCUIT_PRIVATE_KEY: string
  NAMESPACE: string
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface ServiceRow {
  namespace: string
  service: string
  base_url: string
  auth_method: string
  header_name: string
  header_scheme: string
  description: string | null
  spec_url: string | null
  auth_config: string | null
  created_at: string
  updated_at: string
}

export interface CredentialRow {
  namespace: string
  service: string
  identity: string
  encrypted: string
  iv: string
  metadata: string | null
  expires_at: string | null
  created_at: string
  updated_at: string
}

export interface ProxyConstraint {
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  metadata?: Record<string, string>
  ttl?: string | number
}

export interface TokenMintRequest {
  grants: ProxyConstraint[]
}

export interface TokenRestrictRequest {
  token: string
  constraints: ProxyConstraint[]
}
