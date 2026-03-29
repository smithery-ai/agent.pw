import { z } from "zod";
import type { JWKS } from "oauth4webapi";
import type { Result } from "okay-error";
import type { AgentPwError } from "./errors.js";
import type { Database } from "./db/index.js";

export type { Database } from "./db/index.js";

export interface CrudOptions {
  db?: Database;
}

export interface RecursiveCrudOptions extends CrudOptions {
  recursive?: boolean;
}
import type {
  StoredCredentials,
  StoredHeadersCredentials,
  StoredOAuthCredentials,
} from "./lib/credentials-crypto.js";
import type { Logger } from "./lib/logger.js";
import { LTREE_LABEL_PATTERN } from "./paths.js";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

export interface RuleGrant {
  action: string;
  root?: string;
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

export type CredentialProfileAuth = CredentialProfileOAuthAuth | CredentialProfileHeadersAuth;

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
  profilePath: string | null;
  resource?: string;
}

export interface HeadersCredentialAuth extends CredentialAuthBase {
  kind: "headers";
}

export interface OAuthCredentialAuth extends CredentialAuthBase {
  kind: "oauth";
}

export type CredentialAuth = HeadersCredentialAuth | OAuthCredentialAuth;

interface CredentialAuthInputBase {
  profilePath?: string;
  label?: string;
  resource?: string;
}

export interface HeadersCredentialAuthInput extends CredentialAuthInputBase {
  kind: "headers";
}

export interface OAuthCredentialAuthInput extends CredentialAuthInputBase {
  kind: "oauth";
}

export type CredentialAuthInput = HeadersCredentialAuthInput | OAuthCredentialAuthInput;

export interface CredentialSummary {
  path: string;
  auth: CredentialAuth;
  createdAt: Date;
  updatedAt: Date;
}

export interface CredentialRecord extends CredentialSummary {
  secret: StoredCredentials;
}

interface CredentialPutInputBase<TAuth extends CredentialAuthInput, TSecret> {
  path: string;
  resource?: string;
  auth: TAuth;
  secret: TSecret | Buffer;
}

export type CredentialPutInput =
  | CredentialPutInputBase<HeadersCredentialAuthInput, StoredHeadersCredentials>
  | CredentialPutInputBase<OAuthCredentialAuthInput, StoredOAuthCredentials>;

export interface OAuthClientMetadataInput {
  clientId?: string;
  redirectUris: string[];
  clientName?: string;
  scope?: string | string[];
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | "private_key_jwt";
  jwksUri?: string;
  jwks?: JWKS;
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

export const LtreeLabelSchema = z
  .string()
  .regex(LTREE_LABEL_PATTERN, "Invalid ltree label")
  .meta({ id: "LtreeLabel" });
export type LtreeLabel = z.infer<typeof LtreeLabelSchema>;

export const LtreePathSchema = z.string().meta({ id: "LtreePath" });
export type LtreePath = z.infer<typeof LtreePathSchema>;

const OAuthClientAuthenticationMethodSchema = z.enum([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);

interface ConnectOptionBase {
  kind: "oauth" | "headers";
  source: "discovery" | "profile";
  resource: string;
  label: string;
  profilePath?: string;
}

const ConnectOptionBaseSchema = z.object({
  source: z.enum(["discovery", "profile"]),
  resource: z.string(),
  label: z.string(),
  profilePath: LtreePathSchema.optional(),
});

export const OAuthResolvedConfigSchema = z
  .object({
    clientId: z.string(),
    resource: z.string(),
    clientAuthentication: OAuthClientAuthenticationMethodSchema,
    issuer: z.string().optional(),
    authorizationUrl: z.string().optional(),
    tokenUrl: z.string().optional(),
    revocationUrl: z.string().optional(),
    clientSecret: z.string().optional(),
    scopes: z.union([z.string(), z.array(z.string())]).optional(),
  })
  .meta({ id: "OAuthResolvedConfig" });
export type OAuthResolvedConfig = z.infer<typeof OAuthResolvedConfigSchema>;

export const ConnectOAuthOptionSchema = ConnectOptionBaseSchema.extend({
  kind: z.literal("oauth"),
  authorizationServer: z.string().optional(),
  scopes: z.array(z.string()).optional(),
}).meta({ id: "ConnectOAuthOption" });
export type ConnectOAuthOption = z.infer<typeof ConnectOAuthOptionSchema>;

export const PendingFlowCredentialSchema = z
  .object({
    profilePath: LtreePathSchema.optional(),
  })
  .meta({ id: "PendingFlowCredential" });
export type PendingFlowCredential = z.infer<typeof PendingFlowCredentialSchema>;

export interface ConnectHeadersOption extends ConnectOptionBase {
  kind: "headers";
  source: "profile";
  fields: readonly HeaderFieldDefinition[];
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

export interface ConnectStartOAuthInput {
  path: string;
  option: ConnectOAuthOption;
  redirectUri: string;
  headers?: Record<string, string>;
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

export interface ConnectCompleteOAuthInput {
  callbackUri: string;
}

export interface ConnectCompleteResult {
  path: string;
  credential: CredentialRecord;
}

export interface ConnectSetHeadersInput {
  path: string;
  headers: Record<string, string>;
  resource?: string;
}

export interface ConnectResolveHeadersInput {
  path: string;
  refresh?: boolean;
}

export interface ConnectDisconnectInput {
  path: string;
  revoke?: "refresh_token" | "access_token" | "both";
}

export const PendingFlowSchema = z
  .object({
    id: z.string(),
    path: LtreePathSchema,
    credential: PendingFlowCredentialSchema,
    headers: z.record(z.string(), z.string()).optional(),
    redirectUri: z.string(),
    codeVerifier: z.string(),
    expiresAt: z.coerce.date(),
    oauthConfig: OAuthResolvedConfigSchema,
  })
  .meta({ id: "PendingFlow" });
export type PendingFlow = z.infer<typeof PendingFlowSchema>;

export const ConnectFlowSchema = z
  .object({
    flowId: z.string(),
    path: LtreePathSchema,
    resource: z.string(),
    profilePath: LtreePathSchema.optional(),
    expiresAt: z.coerce.date(),
  })
  .meta({ id: "ConnectFlow" });
export type ConnectFlow = z.infer<typeof ConnectFlowSchema>;

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
  client_name: string;
  jwks_uri?: string;
  jwks?: JWKS;
  token_endpoint_auth_signing_alg?: string;
}

export interface CimdDocumentInput {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
  scope?: string | string[];
  tokenEndpointAuthMethod?: OAuthClientAuthenticationMethod | "private_key_jwt";
  jwksUri?: string;
  jwks?: JWKS;
  tokenEndpointAuthSigningAlg?: string;
}

export interface ConnectWebHandlers {
  start(
    request: Request,
    input: Omit<ConnectStartOAuthInput, "redirectUri"> & {
      redirectUri?: string;
    },
  ): Promise<Response>;
  callback(request: Request): Promise<Response>;
}

export interface ConnectWebHandlerOptions {
  callbackPath?: string;
  success?(result: ConnectCompleteResult, request: Request): Response | Promise<Response>;
  error?(error: AgentPwError, request: Request): Response | Promise<Response>;
}

export interface ScopedAgentPw {
  connect: {
    prepare(input: ConnectPrepareInput): Promise<Result<ConnectPrepareResult>>;
    getFlow(flowId: string): Promise<Result<ConnectFlow>>;
    startOAuth(input: ConnectStartOAuthInput): Promise<Result<ConnectAuthorizationSession>>;
    completeOAuth(
      input: ConnectCompleteOAuthInput,
      options?: CrudOptions,
    ): Promise<Result<ConnectCompleteResult>>;
    setHeaders(
      input: ConnectSetHeadersInput,
      options?: CrudOptions,
    ): Promise<Result<CredentialRecord>>;
    resolveHeaders(input: ConnectResolveHeadersInput): Promise<Result<Record<string, string>>>;
    disconnect(input: ConnectDisconnectInput): Promise<Result<boolean>>;
  };
  credentials: {
    get(path: string, options?: CrudOptions): Promise<Result<CredentialRecord | null>>;
    list(
      options?: { path?: string; recursive?: boolean } & CrudOptions,
    ): Promise<Result<CredentialSummary[]>>;
    put(input: CredentialPutInput, options?: CrudOptions): Promise<Result<CredentialRecord>>;
    move(fromPath: string, toPath: string, options?: CrudOptions): Promise<Result<boolean>>;
    delete(path: string, options?: RecursiveCrudOptions): Promise<Result<boolean>>;
  };
  profiles: {
    get(path: string, options?: CrudOptions): Promise<Result<CredentialProfileRecord | null>>;
    list(
      options?: { path?: string; recursive?: boolean } & CrudOptions,
    ): Promise<Result<CredentialProfileRecord[]>>;
    put(
      path: string,
      data: CredentialProfilePutInput,
      options?: CrudOptions,
    ): Promise<Result<CredentialProfileRecord>>;
    delete(path: string, options?: RecursiveCrudOptions): Promise<Result<boolean>>;
  };
}

export type AuthorizedAgentPw = ScopedAgentPw;

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
    resolve(
      input: {
        path: string;
        resource: string;
      },
      options?: CrudOptions,
    ): Promise<Result<CredentialProfileRecord | null>>;
  };
  connect: ScopedAgentPw["connect"] & {
    createWebHandlers(options?: ConnectWebHandlerOptions): ConnectWebHandlers;
    createClientMetadataDocument(input: CimdDocumentInput): Result<CimdDocument>;
    createClientMetadataResponse(input: CimdDocumentInput): Result<Response>;
  };
  scope(input: RuleScope): ScopedAgentPw;
}
