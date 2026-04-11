import { z } from "zod";
import type { JWKS } from "oauth4webapi";
import type { Result } from "okay-error";
import type { AgentPwError } from "./errors.js";
import type { Database, DbClient } from "./db/index.js";

export type { Database, DbClient, Transaction } from "./db/index.js";

export interface CrudOptions {
  db?: DbClient;
}

export interface RecursiveCrudOptions extends CrudOptions {
  recursive?: boolean;
}

export type ResponseLike = {
  status: number;
  headers: Headers | Record<string, string | string[] | undefined>;
};
import type {
  StoredCredentials,
  StoredHeadersCredentials,
  StoredOAuthCredentials,
} from "./lib/credentials-crypto.js";
import type { Logger } from "./lib/logger.js";
import { LTREE_LABEL_PATTERN } from "./paths.js";

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "PATCH"
  | "HEAD"
  | "OPTIONS";

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

export type OAuthClientAuthenticationMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post";

export interface HeaderFieldDefinition {
  name: string;
  label: string;
  description?: string;
  prefix?: string;
  secret?: boolean;
}

export interface ConfigFieldDefinitionBase {
  key: string;
  name: string;
  label: string;
  description?: string;
}

export interface HeaderConfigFieldDefinition extends ConfigFieldDefinitionBase {
  transport: "header";
  prefix?: string;
  secret?: boolean;
}

export interface QueryConfigFieldDefinition extends ConfigFieldDefinitionBase {
  transport: "query";
}

export type ConfigFieldDefinition =
  | HeaderConfigFieldDefinition
  | QueryConfigFieldDefinition;

export interface CredentialProfileConfig {
  fields: ConfigFieldDefinition[];
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

export type CredentialProfileAuth =
  | CredentialProfileOAuthAuth
  | CredentialProfileHeadersAuth;

export interface CredentialProfileRecord {
  path: string;
  resourcePatterns: string[];
  auth: CredentialProfileAuth | null;
  config: CredentialProfileConfig | null;
  displayName: string | null;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CredentialProfilePutInput {
  resourcePatterns: string[];
  auth?: CredentialProfileAuth;
  config?: CredentialProfileConfig;
  displayName?: string;
  description?: string;
}

interface CredentialAuthBase {
  profilePath: string | null;
  resource?: string;
}

export interface HeadersCredentialAuth extends CredentialAuthBase {
  kind: "headers";
  pending?: boolean;
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
  pending?: boolean;
}

export interface OAuthCredentialAuthInput extends CredentialAuthInputBase {
  kind: "oauth";
}

export type CredentialAuthInput =
  | HeadersCredentialAuthInput
  | OAuthCredentialAuthInput;

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
  reason:
    | "existing-credential"
    | "matched-profile"
    | "discovered-oauth"
    | "unconfigured"
    | "step-up";
  profilePath: string | null;
  option: ConnectOption | null;
}

export interface ConnectPrepareInput {
  path: string;
  resource: string;
  response?: ResponseLike;
}

export interface ConnectClassifyResponseInput {
  response?: ResponseLike;
  resource?: string;
}

export type ConnectClassifyResponseResult =
  | { kind: "none" }
  | {
      kind: "auth-required";
      scheme: "bearer";
      scopes: string[];
      resourceMetadataUrl?: URL;
    }
  | {
      kind: "step-up";
      scheme: "bearer";
      scopes: string[];
      resourceMetadataUrl?: URL;
    };

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

export interface ConnectConfigRequiredResult {
  kind: "config_required";
  config: {
    fields: readonly ConfigFieldDefinition[];
    missingKeys: readonly string[];
  };
  resolution: ConnectResolutionResult;
}

export type ConnectPrepareResult =
  | ConnectReadyResult
  | ConnectOptionsResult
  | ConnectConfigRequiredResult;

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
  refresh?: boolean | "force";
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

/**
 * Persistence contract for pending OAuth authorization flows.
 */
export interface FlowStore {
  /** Persist a pending OAuth authorization flow until the callback completes or expires. */
  create(flow: PendingFlow): Promise<void>;
  /** Load a pending OAuth authorization flow by its `state` / flow id. */
  get(id: string): Promise<PendingFlow | null>;
  /** Mark a flow as successfully completed and remove it from storage. */
  complete(id: string): Promise<void>;
  /** Remove a flow without completing it, for example after cancellation or expiry. */
  delete(id: string): Promise<void>;
}

export interface CimdDocument {
  client_id: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  token_endpoint_auth_method:
    | OAuthClientAuthenticationMethod
    | "private_key_jwt";
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

/**
 * Web-friendly OAuth handlers returned by `agentPw.connect.createWebHandlers()`.
 */
export interface ConnectWebHandlers {
  /** Start an OAuth authorization request and redirect the browser to the authorization server. */
  start(
    request: Request,
    input: Omit<ConnectStartOAuthInput, "redirectUri"> & {
      redirectUri?: string;
    },
  ): Promise<Response>;
  /** Finish an OAuth callback request and return the configured success or error response. */
  callback(request: Request): Promise<Response>;
}

/**
 * Customize the browser-oriented helpers returned by `agentPw.connect.createWebHandlers()`.
 */
export interface ConnectWebHandlerOptions {
  /** Relative callback path used when `start()` derives a redirect URI from the incoming request. */
  callbackPath?: string;
  /** Override the default success page returned after a callback completes. */
  success?(
    result: ConnectCompleteResult,
    request: Request,
  ): Response | Promise<Response>;
  /** Override the default JSON error response returned for callback failures. */
  error?(error: AgentPwError, request: Request): Response | Promise<Response>;
}

/**
 * Path-scoped agent.pw API. Instances created with `agentPw.scope(...)` enforce the rights
 * used to construct them and expose the same credential, profile, and connect operations.
 */
export interface ScopedAgentPw {
  connect: {
    /**
     * Resolve an existing credential for `path`, or return the ordered auth options needed to
     * connect `path` to `resource`.
     */
    prepare(input: ConnectPrepareInput): Promise<Result<ConnectPrepareResult>>;
    /** Inspect an HTTP response and classify whether it requests bearer auth or step-up auth. */
    classifyResponse(
      input: ConnectClassifyResponseInput,
    ): Promise<Result<ConnectClassifyResponseResult>>;
    /** Load a pending OAuth flow so a UI can resume or inspect it. */
    getFlow(flowId: string): Promise<Result<ConnectFlow>>;
    /** Begin an OAuth authorization code flow from a previously returned OAuth option. */
    startOAuth(
      input: ConnectStartOAuthInput,
    ): Promise<Result<ConnectAuthorizationSession>>;
    /** Complete an OAuth callback and persist the resulting credential. */
    completeOAuth(
      input: ConnectCompleteOAuthInput,
      options?: CrudOptions,
    ): Promise<Result<ConnectCompleteResult>>;
    /** Persist user-provided header credentials for a path. */
    setHeaders(
      input: ConnectSetHeadersInput,
      options?: CrudOptions,
    ): Promise<Result<CredentialRecord>>;
    /** Resolve ready-to-send headers, refreshing OAuth credentials when needed. */
    resolveHeaders(
      input: ConnectResolveHeadersInput,
    ): Promise<Result<Record<string, string>>>;
    /** Delete a credential and optionally revoke its remote OAuth token(s). */
    disconnect(input: ConnectDisconnectInput): Promise<Result<boolean>>;
  };
  credentials: {
    /** Load a stored credential by its canonical path. */
    get(
      path: string,
      options?: CrudOptions,
    ): Promise<Result<CredentialRecord | null>>;
    /** List credentials under an optional path prefix. */
    list(
      options?: { path?: string; recursive?: boolean } & CrudOptions,
    ): Promise<Result<CredentialSummary[]>>;
    /** Insert or update a credential record. */
    put(
      input: CredentialPutInput,
      options?: CrudOptions,
    ): Promise<Result<CredentialRecord>>;
    /** Move a credential from one canonical path to another. */
    move(
      fromPath: string,
      toPath: string,
      options?: CrudOptions,
    ): Promise<Result<boolean>>;
    /** Delete a credential, optionally including descendants. */
    delete(
      path: string,
      options?: RecursiveCrudOptions,
    ): Promise<Result<boolean>>;
  };
  profiles: {
    /** Load a credential profile by path. */
    get(
      path: string,
      options?: CrudOptions,
    ): Promise<Result<CredentialProfileRecord | null>>;
    /** List credential profiles under an optional path prefix. */
    list(
      options?: { path?: string; recursive?: boolean } & CrudOptions,
    ): Promise<Result<CredentialProfileRecord[]>>;
    /** Insert or update a credential profile. */
    put(
      path: string,
      data: CredentialProfilePutInput,
      options?: CrudOptions,
    ): Promise<Result<CredentialProfileRecord>>;
    /** Delete a credential profile, optionally including descendants. */
    delete(
      path: string,
      options?: RecursiveCrudOptions,
    ): Promise<Result<boolean>>;
  };
}

export type AuthorizedAgentPw = ScopedAgentPw;

/**
 * Configuration for `createAgentPw()`.
 */
export interface AgentPwOptions {
  /** Drizzle database or transaction used to read and write agent.pw tables. */
  db: Database;
  /** Secret used to encrypt credentials before they are stored. */
  encryptionKey: string;
  /** Override the clock used for flow expiry and token refresh timing. */
  clock?: () => Date;
  /** Logger implementation for debug and operational messages. */
  logger?: Logger;
  /** Storage backend for pending OAuth browser flows. Required for OAuth redirects. */
  flowStore?: FlowStore;
  /** Custom fetch implementation for OAuth discovery, token, and revocation requests. */
  oauthFetch?: typeof fetch;
  /** Custom SQL schema or table prefix for agent.pw tables. */
  sql?: SqlNamespaceOptions;
  /** Default OAuth client configuration used when profiles or discovery do not provide one. */
  oauthClient?: OAuthClientInput;
}

/**
 * Full agent.pw API returned by `createAgentPw()`.
 */
export interface AgentPw extends ScopedAgentPw {
  profiles: ScopedAgentPw["profiles"] & {
    /** Resolve the most specific credential profile that matches a path and resource. */
    resolve(
      input: {
        path: string;
        resource: string;
      },
      options?: CrudOptions,
    ): Promise<Result<CredentialProfileRecord | null>>;
  };
  connect: ScopedAgentPw["connect"] & {
    /** Create browser-style OAuth start and callback handlers for web frameworks. */
    createWebHandlers(options?: ConnectWebHandlerOptions): ConnectWebHandlers;
    /** Build an RFC 7591 client metadata document from friendly input. */
    createClientMetadataDocument(
      input: CimdDocumentInput,
    ): Result<CimdDocument>;
    /** Return the client metadata document as a JSON `Response`. */
    createClientMetadataResponse(input: CimdDocumentInput): Result<Response>;
  };
  /** Derive a restricted API view that enforces the supplied rights on every operation. */
  scope(input: RuleScope): ScopedAgentPw;
}
