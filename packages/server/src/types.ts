import type { Database } from './db/index.js'
import type { Logger } from './lib/logger.js'
import type { StoredCredentials } from './lib/credentials-crypto.js'
import type { FlowStore } from './oauth.js'

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface TokenRight {
  action: string
  root: string
}

export interface TokenFacts {
  rights: TokenRight[]
  userId: string | null
  orgId: string | null
  homePath: string | null
  scopes: string[]
}

export interface TokenConstraint {
  actions?: string | string[]
  hosts?: string | string[]
  roots?: string | string[]
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  ttl?: string | number
}

export interface AgentPwOptions {
  db: Database
  biscuitPrivateKey: string
  encryptionKey?: string
  clock?: () => Date
  logger?: Logger
  flowStore?: FlowStore
}

export interface CredentialProfileRecord {
  path: string
  provider: string
  host: string[]
  auth: Record<string, unknown> | null
  oauthConfig: Record<string, unknown> | null
  displayName: string | null
  description: string | null
  createdAt: Date
  updatedAt: Date
}

export interface CredentialProfilePutInput {
  host: string[]
  auth?: Record<string, unknown>
  oauthConfig?: Record<string, unknown>
  displayName?: string
  description?: string
}

export interface CredentialSummary {
  profilePath: string
  host: string | null
  path: string
  auth: Record<string, unknown>
  createdAt: Date
  updatedAt: Date
}

export interface CredentialRecord extends CredentialSummary {
  secret: StoredCredentials
}

export interface CredentialPutInput {
  profilePath: string
  host?: string | null
  auth?: Record<string, unknown>
  secret: StoredCredentials | Buffer
}

export interface BindingRef {
  root: string
  profilePath: string
}

export interface ResolvedCredential extends CredentialRecord {
  profile: CredentialProfileRecord | null
}

export interface BindingPutInput extends BindingRef {
  credentialPath?: string
  host?: string | null
  auth?: Record<string, unknown>
  secret: StoredCredentials | Buffer
}

export interface AccessOwner {
  subject?: string
  userId?: string | null
  orgId?: string | null
  homePath?: string | null
  scopes?: string[]
  name?: string | null
}

export interface MintAccessInput {
  rights: TokenRight[]
  constraints?: TokenConstraint[]
  owner?: AccessOwner
}

export interface AuthorizeAccessInput {
  token: string
  host: string
  method: HttpMethod
  path: string
  root: string
  action?: string
}

export interface AccessInspection {
  valid: boolean
  rights: TokenRight[]
  userId: string | null
  orgId: string | null
  homePath: string | null
  scopes: string[]
  expiresAt: Date | null
  revoked: boolean
  revocationIds: string[]
  trackedTokenId: string | null
}

export interface AuthorizationResult {
  authorized: boolean
  error?: string
  facts?: TokenFacts
  trackedTokenId?: string | null
}

export interface AgentPw {
  profiles: {
    resolve(input: {
      provider?: string
      host?: string
      root: string
    }): Promise<CredentialProfileRecord | null>
    get(path: string): Promise<CredentialProfileRecord | null>
    list(options?: {
      root?: string
    }): Promise<CredentialProfileRecord[]>
    put(path: string, data: CredentialProfilePutInput): Promise<CredentialProfileRecord>
    delete(path: string): Promise<boolean>
  }
  bindings: {
    resolve(input: BindingRef & {
      credentialPath?: string
    }): Promise<ResolvedCredential | null>
    resolveHeaders(input: BindingRef & {
      credentialPath?: string
    }): Promise<Record<string, string>>
    put(input: BindingPutInput): Promise<ResolvedCredential>
  }
  credentials: {
    resolve(input: {
      root: string
      profilePath: string
      credentialPath?: string
    }): Promise<CredentialRecord | null>
    get(path: string): Promise<CredentialRecord | null>
    list(options?: {
      root?: string
    }): Promise<CredentialSummary[]>
    put(path: string, input: CredentialPutInput): Promise<CredentialRecord>
    move(fromPath: string, toPath: string): Promise<boolean>
    delete(path: string): Promise<boolean>
  }
  oauth: {
    start(input: BindingRef & {
      id?: string
      codeVerifier?: string
      expiresAt?: Date
    }): Promise<{
      id: string
      root: string
      profilePath: string
      codeVerifier: string
      expiresAt: Date
    }>
    get(id: string): Promise<{
      id: string
      root: string
      profilePath: string
      codeVerifier: string
      expiresAt: Date
    } | null>
    complete(id: string, result?: {
      identity?: string
    }): Promise<void>
    delete(id: string): Promise<void>
  }
  access: {
    mint(input: MintAccessInput): Promise<{
      id: string
      token: string
      expiresAt: Date | null
      revocationIds: string[]
    }>
    inspect(token: string): Promise<AccessInspection>
    restrict(token: string, constraints: TokenConstraint[]): string
    revoke(id: string, reason?: string): Promise<boolean>
    authorize(input: AuthorizeAccessInput): Promise<AuthorizationResult>
  }
}
