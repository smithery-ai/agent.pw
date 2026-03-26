import type { Result } from "okay-error";
import type { Database } from "./db/index.js";
import type { StoredCredentials } from "./lib/credentials-crypto.js";
import type { Logger } from "./lib/logger.js";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

interface AgentPwErrorBase {
  message: string;
  cause?: unknown;
  path?: string;
}

export interface AgentPwInputError extends AgentPwErrorBase {
  type: "Input";
  field?: string;
  value?: string;
}

export interface AgentPwConflictError extends AgentPwErrorBase {
  type: "Conflict";
}

export interface AgentPwAuthorizationError extends AgentPwErrorBase {
  type: "Authorization";
  action: string;
}

export interface AgentPwNotFoundError extends AgentPwErrorBase {
  type: "NotFound";
  resource: string;
}

export interface AgentPwExpiredError extends AgentPwErrorBase {
  type: "Expired";
  resource: string;
}

export interface AgentPwUnsupportedCredentialKindError extends AgentPwErrorBase {
  type: "UnsupportedCredentialKind";
  kind: "oauth" | "headers" | "env";
}

export interface AgentPwPersistenceError extends AgentPwErrorBase {
  type: "Persistence";
  operation: string;
}

export interface AgentPwOAuthError extends AgentPwErrorBase {
  type: "OAuth";
  stage: string;
}

export interface AgentPwCryptoError extends AgentPwErrorBase {
  type: "Crypto";
  operation: string;
}

export interface AgentPwInternalError extends AgentPwErrorBase {
  type: "Internal";
  source?: string;
}

export type AgentPwError =
  | AgentPwAuthorizationError
  | AgentPwConflictError
  | AgentPwCryptoError
  | AgentPwExpiredError
  | AgentPwInputError
  | AgentPwInternalError
  | AgentPwNotFoundError
  | AgentPwOAuthError
  | AgentPwPersistenceError
  | AgentPwUnsupportedCredentialKindError;

export type AgentPwResult<ValueType, ErrorType extends AgentPwError = AgentPwError> = Result<
  ValueType,
  ErrorType
>;

export interface RuleGrant {
  action: string;
  root: string;
}

export interface RuleConstraint {
  actions?: string | string[];
  hosts?: string | string[];
  roots?: string | string[];
  services?: string | string[];
  methods?: HttpMethod | HttpMethod[];
  paths?: string | string[];
  ttl?: string | number;
}

export interface RuleScope {
  rights: RuleGrant[];
}

export interface BiscuitSubject {
  orgId?: string | null;
  homePath?: string | null;
  scopes?: string[];
}

export interface BiscuitTokenFacts extends RuleScope {
  userId: string | null;
  orgId: string | null;
  homePath: string | null;
  scopes: string[];
}

export interface RuleAuthorizationInput {
  rights: RuleGrant[];
  action: string;
  path: string;
}

export interface RuleAuthorizationResult {
  authorized: boolean;
  error?: string;
}

export interface SqlNamespaceOptions {
  schema?: string;
  tablePrefix?: string;
}

export type OAuthClientAuthenticationMethod = "none" | "client_secret_basic" | "client_secret_post";

export interface HeaderFieldDefinition {
  name: string;
  label: string;
  description?: string;
  prefix?: string;
  secret?: boolean;
}

export interface EnvFieldDefinition {
  name: string;
  label: string;
  description?: string;
  secret?: boolean;
}

export interface CredentialProfileOAuthAuth {
  kind: "oauth";
  label?: string;
  issuer?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  revocationUrl?: string;
  clientId?: string;
  clientSecret?: string;
  clientAuthentication?: OAuthClientAuthenticationMethod;
  scopes?: string | string[];
}

export interface CredentialProfileHeadersAuth {
  kind: "headers";
  label?: string;
  fields: HeaderFieldDefinition[];
}

export interface CredentialProfileEnvAuth {
  kind: "env";
  label?: string;
  fields: EnvFieldDefinition[];
}

export type CredentialProfileAuth =
  | CredentialProfileOAuthAuth
  | CredentialProfileHeadersAuth
  | CredentialProfileEnvAuth;

export interface CredentialProfileRecord {
  path: string;
  resourcePatterns: string[];
  auth: CredentialProfileAuth;
  displayName: string | null;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CredentialProfilePutInput {
  resourcePatterns: string[];
  auth: CredentialProfileAuth;
  displayName?: string;
  description?: string;
}

interface CredentialAuthBase {
  profilePath?: string | null;
  label?: string | null;
  resource?: string | null;
}

export interface HeadersCredentialAuth extends CredentialAuthBase {
  kind: "headers";
}

export interface OAuthCredentialAuth extends CredentialAuthBase {
  kind: "oauth";
}

export interface EnvCredentialAuth extends CredentialAuthBase {
  kind: "env";
}

export type CredentialAuth = HeadersCredentialAuth | OAuthCredentialAuth | EnvCredentialAuth;

export interface CredentialSummary {
  path: string;
  auth: CredentialAuth;
  createdAt: Date;
  updatedAt: Date;
}

export interface CredentialRecord extends CredentialSummary {
  secret: StoredCredentials;
}

export interface CredentialPutInput {
  path: string;
  resource?: string;
  auth: CredentialAuth;
  secret: StoredCredentials | Buffer;
}

export interface OAuthClientMetadataInput {
  clientId?: string;
  redirectUris: string[];
  clientName?: string;
  scope?: string | string[];
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | "private_key_jwt";
  jwksUri?: string;
  jwks?: Record<string, unknown>;
  tokenEndpointAuthSigningAlg?: string;
}

export interface OAuthClientInput {
  clientId?: string;
  clientSecret?: string;
  clientAuthentication?: OAuthClientAuthenticationMethod;
  metadata?: OAuthClientMetadataInput;
  useDynamicRegistration?: boolean;
  initialAccessToken?: string;
}

export interface OAuthResolvedConfig {
  issuer?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  revocationUrl?: string;
  clientId: string;
  clientSecret?: string;
  clientAuthentication: OAuthClientAuthenticationMethod;
  scopes?: string | string[];
  resource: string;
}

interface ConnectOptionBase {
  kind: "oauth" | "headers";
  source: "discovery" | "profile";
  resource: string;
  label: string;
  profilePath?: string;
}

export interface ConnectOAuthOption extends ConnectOptionBase {
  kind: "oauth";
  authorizationServer?: string;
  scopes?: string[];
}

export interface ConnectHeadersOption extends ConnectOptionBase {
  kind: "headers";
  source: "profile";
  fields: HeaderFieldDefinition[];
}

export type ConnectOption = ConnectOAuthOption | ConnectHeadersOption;

export interface ConnectResolutionResult {
  canonicalResource: string;
  source: ConnectOption["source"] | null;
  reason: "existing-credential" | "matched-profile" | "discovered-oauth" | "unconfigured";
  profilePath: string | null;
  option: ConnectOption | null;
}

export interface ConnectPrepareInput {
  path: string;
  resource: string;
  response?: Response;
}

export interface ConnectReadyResult {
  kind: "ready";
  credential: CredentialRecord;
  headers: Record<string, string>;
  resolution: ConnectResolutionResult;
}

export interface ConnectOptionsResult {
  kind: "options";
  options: ConnectOption[];
  resolution: ConnectResolutionResult;
}

export type ConnectPrepareResult = ConnectReadyResult | ConnectOptionsResult;

export interface ConnectStartInput {
  path: string;
  option: ConnectOAuthOption;
  redirectUri: string;
  scopes?: string | string[];
  expiresAt?: Date;
  additionalParameters?: Record<string, string>;
  client?: OAuthClientInput;
}

export interface ConnectAuthorizationSession {
  flowId: string;
  authorizationUrl: string;
  expiresAt: Date;
  path: string;
  resource: string;
  option: ConnectOAuthOption;
}

export interface ConnectCompleteInput {
  callbackUri: string;
  preserveExistingHeaders?: boolean;
}

export interface ConnectCompleteResult {
  path: string;
  credential: CredentialRecord;
}

export interface ConnectSaveHeadersInput {
  path: string;
  option: ConnectHeadersOption;
  values: Record<string, string>;
}

export interface ConnectHeadersInput {
  path: string;
  refresh?: boolean;
}

export interface ConnectDisconnectInput {
  path: string;
  revoke?: "refresh_token" | "access_token" | "both";
}

export interface PendingFlow {
  id: string;
  path: string;
  resource: string;
  option: ConnectOAuthOption;
  redirectUri: string;
  codeVerifier: string;
  expiresAt: Date;
  oauthConfig: OAuthResolvedConfig;
}

export interface ConnectFlow {
  flowId: string;
  path: string;
  resource: string;
  option: ConnectOAuthOption;
  expiresAt: Date;
}

export interface FlowStore {
  create(flow: PendingFlow): Promise<void>;
  get(id: string): Promise<PendingFlow | null>;
  complete(id: string): Promise<void>;
  delete(id: string): Promise<void>;
}

export interface CimdDocument {
  client_id: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  token_endpoint_auth_method: OAuthClientAuthenticationMethod | "private_key_jwt";
  scope?: string;
  client_name?: string;
  jwks_uri?: string;
  jwks?: Record<string, unknown>;
  token_endpoint_auth_signing_alg?: string;
}

export interface CimdDocumentInput {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
  scope?: string | string[];
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | "private_key_jwt";
  jwksUri?: string;
  jwks?: Record<string, unknown>;
  tokenEndpointAuthSigningAlg?: string;
}

export interface ConnectWebHandlers {
  start(
    request: Request,
    input: Omit<ConnectStartInput, "redirectUri"> & {
      redirectUri?: string;
    },
  ): Promise<Response>;
  callback(request: Request): Promise<Response>;
}

export interface ScopedAgentPw {
  connect: {
    prepare(input: ConnectPrepareInput): Promise<AgentPwResult<ConnectPrepareResult>>;
    getFlow(flowId: string): Promise<AgentPwResult<ConnectFlow>>;
    start(input: ConnectStartInput): Promise<AgentPwResult<ConnectAuthorizationSession>>;
    complete(input: ConnectCompleteInput): Promise<AgentPwResult<ConnectCompleteResult>>;
    saveHeaders(input: ConnectSaveHeadersInput): Promise<AgentPwResult<CredentialRecord>>;
    headers(input: ConnectHeadersInput): Promise<AgentPwResult<Record<string, string>>>;
    disconnect(input: ConnectDisconnectInput): Promise<AgentPwResult<boolean>>;
  };
  credentials: {
    get(path: string): Promise<AgentPwResult<CredentialRecord | null>>;
    list(options?: { path?: string }): Promise<AgentPwResult<CredentialSummary[]>>;
    put(input: CredentialPutInput): Promise<AgentPwResult<CredentialRecord>>;
    move(fromPath: string, toPath: string): Promise<AgentPwResult<boolean>>;
    delete(path: string): Promise<AgentPwResult<boolean>>;
  };
  profiles: {
    get(path: string): Promise<AgentPwResult<CredentialProfileRecord | null>>;
    list(options?: { path?: string }): Promise<AgentPwResult<CredentialProfileRecord[]>>;
    put(
      path: string,
      data: CredentialProfilePutInput,
    ): Promise<AgentPwResult<CredentialProfileRecord>>;
    delete(path: string): Promise<AgentPwResult<boolean>>;
  };
}

export type AuthorizedAgentPw = ScopedAgentPw;
export type RuleFacts = BiscuitTokenFacts;
export type RuleSubject = BiscuitSubject;

export interface AgentPwOptions {
  db: Database;
  encryptionKey: string;
  clock?: () => Date;
  logger?: Logger;
  flowStore?: FlowStore;
  oauthFetch?: typeof fetch;
  sql?: SqlNamespaceOptions;
  oauthClient?: OAuthClientInput;
}

export interface AgentPw extends ScopedAgentPw {
  profiles: ScopedAgentPw["profiles"] & {
    resolve(input: {
      path: string;
      resource: string;
    }): Promise<AgentPwResult<CredentialProfileRecord | null>>;
  };
  connect: ScopedAgentPw["connect"] & {
    createWebHandlers(options?: {
      callbackPath?: string;
      success?(result: ConnectCompleteResult, request: Request): Response | Promise<Response>;
      error?(error: AgentPwError, request: Request): Response | Promise<Response>;
    }): ConnectWebHandlers;
    createClientMetadataDocument(input: CimdDocumentInput): AgentPwResult<CimdDocument>;
    createClientMetadataResponse(input: CimdDocumentInput): AgentPwResult<Response>;
  };
  scope(input: RuleScope): ScopedAgentPw;
}
