import type { Database } from './db/index.js'
import type { Logger } from './lib/logger.js'
import type { StoredCredentials } from './lib/credentials-crypto.js'

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS'

export interface RuleGrant {
  action: string
  root: string
}

export interface RuleConstraint {
  actions?: string | string[]
  hosts?: string | string[]
  roots?: string | string[]
  services?: string | string[]
  methods?: HttpMethod | HttpMethod[]
  paths?: string | string[]
  ttl?: string | number
}

export interface RuleSubject {
  subject?: string
  userId?: string | null
  orgId?: string | null
  // Optional legacy metadata for consumers that still model a primary namespace.
  homePath?: string | null
  scopes?: string[]
}

export interface RuleFacts {
  rights: RuleGrant[]
  userId: string | null
  orgId: string | null
  // Optional legacy metadata; not required by the binding-first runtime model.
  homePath: string | null
  scopes: string[]
}

export interface RuleAuthorizationInput {
  rights: RuleGrant[]
  action: string
  path: string
}

export interface RuleAuthorizationResult {
  authorized: boolean
  error?: string
}

export interface SqlNamespaceOptions {
  schema?: string
  tablePrefix?: string
}

export type OAuthClientAuthenticationMethod =
  | 'none'
  | 'client_secret_basic'
  | 'client_secret_post'

export interface OAuthProfileConfig {
  issuer?: string
  authorizationUrl?: string
  tokenUrl?: string
  revocationUrl?: string
  clientId: string
  clientSecret?: string
  clientAuthentication: OAuthClientAuthenticationMethod
  scopes?: string | string[]
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
  profilePath: string | null
  target: AuthTarget
  host: string | null
  path: string
  auth: Record<string, unknown>
  createdAt: Date
  updatedAt: Date
}

export interface CredentialRecord extends CredentialSummary {
  secret: StoredCredentials
}

export interface ProfileAuthTarget {
  kind: 'profile'
  profilePath: string
}

export interface ResourceAuthTarget {
  kind: 'resource'
  resource: string
  authorizationServer?: string
}

export type AuthTarget = ProfileAuthTarget | ResourceAuthTarget

export type CredentialPutInput = ({
  profilePath: string
  target?: never
} | {
  target: AuthTarget
  profilePath?: never
}) & {
  host?: string | null
  auth?: Record<string, unknown>
  secret: StoredCredentials | Buffer
}

export interface ProfileAuthBinding {
  root: string
  profilePath: string
  target?: never
}

export interface TargetAuthBinding {
  root: string
  target: AuthTarget
  profilePath?: never
}

export type AuthBinding = ProfileAuthBinding | TargetAuthBinding

// Backward-compatible aliases for the earlier binding-first API names.
export type ProfileBindingRef = ProfileAuthBinding
export type TargetBindingRef = TargetAuthBinding
export type BindingRef = AuthBinding

export interface ResolvedCredential extends CredentialRecord {
  profile: CredentialProfileRecord | null
}

export type BindingPutInput = AuthBinding & {
  credentialPath?: string
  host?: string | null
  auth?: Record<string, unknown>
  secret: StoredCredentials | Buffer
}

export interface OAuthClientMetadataInput {
  clientId?: string
  redirectUris: string[]
  clientName?: string
  scope?: string | string[]
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | 'private_key_jwt'
  jwksUri?: string
  jwks?: Record<string, unknown>
  tokenEndpointAuthSigningAlg?: string
}

export interface OAuthClientInput {
  clientId?: string
  clientSecret?: string
  clientAuthentication?: OAuthClientAuthenticationMethod
  metadata?: OAuthClientMetadataInput
  useDynamicRegistration?: boolean
  initialAccessToken?: string
}

export interface OAuthResolvedConfig extends OAuthProfileConfig {
  resource?: string
}

export interface PendingFlow {
  id: string
  root: string
  target: AuthTarget
  credentialPath?: string
  redirectUri: string
  codeVerifier: string
  expiresAt: Date
  oauthConfig: OAuthResolvedConfig
}

export interface CompletedFlowResult {
  identity?: string
}

export interface FlowStore {
  create(flow: PendingFlow): Promise<void>
  get(id: string): Promise<PendingFlow | null>
  complete(id: string, result?: CompletedFlowResult): Promise<void>
  delete(id: string): Promise<void>
}

export type OAuthStartAuthorizationInput = AuthBinding & {
  credentialPath?: string
  redirectUri: string
  scopes?: string | string[]
  expiresAt?: Date
  additionalParameters?: Record<string, string>
  client?: OAuthClientInput
}

export interface OAuthAuthorizationSession {
  flowId: string
  authorizationUrl: string
  expiresAt: Date
  root: string
  target: AuthTarget
  profilePath: string | null
  credentialPath?: string
}

export interface OAuthCompleteAuthorizationInput {
  callbackUri: string
}

export interface OAuthCompletionResult {
  binding: AuthBinding
  credentialPath: string
  credential: ResolvedCredential
}

export type OAuthRefreshInput = AuthBinding & {
  credentialPath?: string
  force?: boolean
}

export type OAuthDisconnectInput = AuthBinding & {
  credentialPath?: string
  revoke?: 'refresh_token' | 'access_token' | 'both'
}

export interface CimdDocument {
  client_id: string
  redirect_uris: string[]
  response_types: string[]
  grant_types: string[]
  token_endpoint_auth_method: OAuthClientAuthenticationMethod | 'private_key_jwt'
  scope?: string
  client_name?: string
  jwks_uri?: string
  jwks?: Record<string, unknown>
  token_endpoint_auth_signing_alg?: string
}

export interface CimdDocumentInput {
  clientId: string
  redirectUris: string[]
  clientName?: string
  scope?: string | string[]
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | 'private_key_jwt'
  jwksUri?: string
  jwks?: Record<string, unknown>
  tokenEndpointAuthSigningAlg?: string
}

export interface OAuthWebHandlers {
  start(request: Request, input: Omit<OAuthStartAuthorizationInput, 'redirectUri'> & {
    redirectUri?: string
  }): Promise<Response>
  callback(request: Request): Promise<Response>
}

export interface AgentPwOptions {
  db: Database
  encryptionKey: string
  clock?: () => Date
  logger?: Logger
  flowStore?: FlowStore
  oauthFetch?: typeof fetch
  sql?: SqlNamespaceOptions
  oauthClient?: OAuthClientInput
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
    resolve(input: AuthBinding & {
      credentialPath?: string
      refresh?: boolean
    }): Promise<ResolvedCredential | null>
    resolveHeaders(input: AuthBinding & {
      credentialPath?: string
      refresh?: boolean
    }): Promise<Record<string, string>>
    put(input: BindingPutInput): Promise<ResolvedCredential>
  }
  credentials: {
    resolve(input: AuthBinding & {
      credentialPath?: string
      refresh?: boolean
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
    getFlow(id: string): Promise<PendingFlow | null>
    startAuthorization(input: OAuthStartAuthorizationInput): Promise<OAuthAuthorizationSession>
    completeAuthorization(input: OAuthCompleteAuthorizationInput): Promise<OAuthCompletionResult>
    refreshCredential(input: OAuthRefreshInput): Promise<ResolvedCredential | null>
    disconnect(input: OAuthDisconnectInput): Promise<boolean>
    discoverResource(input: {
      resource: string
    }): Promise<{
      target: ResourceAuthTarget
      authorizationServers: string[]
      resourceName?: string
      scopes?: string[]
    }>
    createWebHandlers(options?: {
      callbackPath?: string
      success?(result: OAuthCompletionResult, request: Request): Response | Promise<Response>
      error?(error: unknown, request: Request): Response | Promise<Response>
    }): OAuthWebHandlers
    createClientMetadataDocument(input: CimdDocumentInput): CimdDocument
    createClientMetadataResponse(input: CimdDocumentInput): Response
  }
}
