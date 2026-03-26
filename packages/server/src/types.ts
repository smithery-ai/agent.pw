import type { Database } from "./db/index.js";
import type { StoredCredentials } from "./lib/credentials-crypto.js";
import type { Logger } from "./lib/logger.js";

export type HttpMethod =
	| "GET"
	| "POST"
	| "PUT"
	| "DELETE"
	| "PATCH"
	| "HEAD"
	| "OPTIONS";

export type JsonValue =
	| string
	| number
	| boolean
	| null
	| JsonObject
	| JsonValue[];

export interface JsonObject {
	[key: string]: JsonValue;
}

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

export type CredentialAuth =
	| HeadersCredentialAuth
	| OAuthCredentialAuth
	| EnvCredentialAuth;

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
	source: ConnectOption["source"] | "derived-profile" | null;
	reason:
		| "existing-credential"
		| "matched-profile"
		| "discovered-oauth"
		| "unconfigured";
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
}

export interface ConnectOptionsResult {
	kind: "options";
	options: ConnectOption[];
}

export type ConnectPrepareResult = ConnectReadyResult | ConnectOptionsResult;

export type ConnectStartReason = "manual" | "auth_required";

export interface ConnectStartInput {
	path: string;
	option: ConnectOAuthOption;
	redirectUri: string;
	context?: JsonObject;
	reason?: ConnectStartReason;
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
	context?: JsonObject;
	reason: ConnectStartReason;
	requiresUpstreamAuthorization: boolean;
}

export interface ConnectStartForResourceInput {
	path: string;
	resource: string;
	redirectUri: string;
	response?: Response;
	context?: JsonObject;
	reason?: ConnectStartReason;
	scopes?: string | string[];
	expiresAt?: Date;
	additionalParameters?: Record<string, string>;
	client?: OAuthClientInput;
}

export interface ConnectStartForResourceReadyResult extends ConnectReadyResult {
	resolution: ConnectResolutionResult;
}

export interface ConnectStartForResourceAuthorizationResult
	extends ConnectAuthorizationSession {
	kind: "authorization";
	resolution: ConnectResolutionResult;
}

export interface ConnectStartForResourceHeadersResult {
	kind: "headers";
	option: ConnectHeadersOption;
	resolution: ConnectResolutionResult;
}

export interface ConnectStartForResourceUnconfiguredResult {
	kind: "unconfigured";
	resolution: ConnectResolutionResult;
}

export interface ConnectCompleteInput {
	callbackUri: string;
	merge?: "replace" | "preserve-non-auth-headers";
}

export interface ConnectCompleteResult {
	path: string;
	credential: CredentialRecord;
	context?: JsonObject;
	outcome: "connected";
	reason: ConnectStartReason;
	requiresUpstreamAuthorization: boolean;
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
	context?: JsonObject;
	reason: ConnectStartReason;
	requiresUpstreamAuthorization: boolean;
}

export interface CompletedFlowResult {
	identity?: string;
	context?: JsonObject;
	reason?: ConnectStartReason;
	requiresUpstreamAuthorization?: boolean;
}

export interface ConnectFlow {
	flowId: string;
	path: string;
	resource: string;
	option: ConnectOAuthOption;
	expiresAt: Date;
	context?: JsonObject;
	reason: ConnectStartReason;
	requiresUpstreamAuthorization: boolean;
}

export interface FlowStore {
	create(flow: PendingFlow): Promise<void>;
	get(id: string): Promise<PendingFlow | null>;
	complete(id: string, result?: CompletedFlowResult): Promise<void>;
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
		resolve(input: ConnectPrepareInput): Promise<ConnectResolutionResult>;
		prepare(input: ConnectPrepareInput): Promise<ConnectPrepareResult>;
		getFlow(flowId: string): Promise<ConnectFlow | null>;
		start(input: ConnectStartInput): Promise<ConnectAuthorizationSession>;
		startFromChallenge(
			input: ConnectStartInput,
		): Promise<ConnectAuthorizationSession>;
		startForResource(
			input: ConnectStartForResourceInput,
		): Promise<
			| ConnectStartForResourceReadyResult
			| ConnectStartForResourceAuthorizationResult
			| ConnectStartForResourceHeadersResult
			| ConnectStartForResourceUnconfiguredResult
		>;
		startForResourceFromChallenge(
			input: ConnectStartForResourceInput,
		): Promise<
			| ConnectStartForResourceReadyResult
			| ConnectStartForResourceAuthorizationResult
			| ConnectStartForResourceHeadersResult
			| ConnectStartForResourceUnconfiguredResult
		>;
		complete(input: ConnectCompleteInput): Promise<ConnectCompleteResult>;
		saveHeaders(input: ConnectSaveHeadersInput): Promise<CredentialRecord>;
		headers(input: ConnectHeadersInput): Promise<Record<string, string>>;
		disconnect(input: ConnectDisconnectInput): Promise<boolean>;
	};
	credentials: {
		get(path: string): Promise<CredentialRecord | null>;
		list(options?: { path?: string }): Promise<CredentialSummary[]>;
		put(input: CredentialPutInput): Promise<CredentialRecord>;
		move(fromPath: string, toPath: string): Promise<boolean>;
		delete(path: string): Promise<boolean>;
	};
	profiles: {
		get(path: string): Promise<CredentialProfileRecord | null>;
		list(options?: { path?: string }): Promise<CredentialProfileRecord[]>;
		put(
			path: string,
			data: CredentialProfilePutInput,
		): Promise<CredentialProfileRecord>;
		delete(path: string): Promise<boolean>;
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
		}): Promise<CredentialProfileRecord | null>;
	};
	connect: ScopedAgentPw["connect"] & {
		createWebHandlers(options?: {
			callbackPath?: string;
			success?(
				result: ConnectCompleteResult,
				request: Request,
			): Response | Promise<Response>;
			error?(error: unknown, request: Request): Response | Promise<Response>;
		}): ConnectWebHandlers;
		createClientMetadataDocument(input: CimdDocumentInput): CimdDocument;
		createClientMetadataResponse(input: CimdDocumentInput): Response;
	};
	scope(input: RuleScope): ScopedAgentPw;
}
