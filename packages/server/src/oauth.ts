import * as oauth from "oauth4webapi";
import { AgentPwInputError } from "./errors.js";
import {
	buildCredentialHeaders,
	type StoredCredentials,
} from "./lib/credentials-crypto.js";
import { isRecord, randomId, validateFlowId } from "./lib/utils.js";
import { normalizeResource } from "./resource-patterns.js";
import type {
	CimdDocument,
	CimdDocumentInput,
	CompletedFlowResult,
	ConnectAuthorizationSession,
	ConnectCompleteInput,
	ConnectCompleteResult,
	ConnectDisconnectInput,
	ConnectOAuthOption,
	ConnectStartInput,
	ConnectWebHandlers,
	CredentialProfileRecord,
	CredentialPutInput,
	CredentialRecord,
	FlowStore,
	JsonObject,
	JsonValue,
	OAuthClientAuthenticationMethod,
	OAuthClientInput,
	OAuthResolvedConfig,
	PendingFlow,
} from "./types.js";

function assertPath(path: string, label: string) {
	if (!path.startsWith("/") || path === "/" || path.includes("..")) {
		throw new AgentPwInputError(`Invalid ${label} '${path}'`);
	}
	return path;
}

function assertUrl(value: string, label: string) {
	try {
		return new URL(value);
	} catch {
		throw new AgentPwInputError(`Invalid ${label} '${value}'`);
	}
}

function stringValue(value: unknown) {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isJsonValue(value: unknown): value is JsonValue {
	return (
		value === null ||
		typeof value === "string" ||
		typeof value === "number" ||
		typeof value === "boolean" ||
		(Array.isArray(value) && value.every(isJsonValue)) ||
		isJsonObject(value)
	);
}

function isJsonObject(value: unknown): value is JsonObject {
	return isRecord(value) && Object.values(value).every(isJsonValue);
}

function jsonObject(value: unknown, label: string): JsonObject | undefined {
	if (value == null) {
		return undefined;
	}
	const normalized = JSON.parse(JSON.stringify(value));
	if (!isJsonObject(normalized)) {
		throw new AgentPwInputError(`${label} must be a JSON object`);
	}
	return normalized;
}

function toScopeString(value: string | string[] | undefined) {
	return Array.isArray(value) ? value.join(" ") : value;
}

function defaultExpiry(clock: () => Date) {
	return new Date(clock().getTime() + 10 * 60 * 1000);
}

function normalizeStartReason(
	value: ConnectStartInput["reason"],
): PendingFlow["reason"] {
	return value === "auth_required" ? "auth_required" : "manual";
}

function normalizeClientAuthentication(
	value: string | undefined,
	hasSecret: boolean,
): OAuthClientAuthenticationMethod {
	if (
		value === "client_secret_basic" ||
		value === "client_secret_post" ||
		value === "none"
	) {
		return value;
	}
	return hasSecret ? "client_secret_basic" : "none";
}

function buildClientAuthentication(config: OAuthResolvedConfig) {
	switch (config.clientAuthentication) {
		case "client_secret_post":
			if (!config.clientSecret) {
				throw new AgentPwInputError(
					"OAuth client_secret_post requires clientSecret",
				);
			}
			return oauth.ClientSecretPost(config.clientSecret);
		case "client_secret_basic":
			if (!config.clientSecret) {
				throw new AgentPwInputError(
					"OAuth client_secret_basic requires clientSecret",
				);
			}
			return oauth.ClientSecretBasic(config.clientSecret);
		case "none":
			return oauth.None();
	}
}

function buildClient(config: OAuthResolvedConfig): oauth.Client {
	return {
		client_id: config.clientId,
	};
}

function resourceFromCredentialRecord(credential: CredentialRecord) {
	if (
		typeof credential.auth.resource === "string" &&
		credential.auth.resource.length > 0
	) {
		return credential.auth.resource;
	}

	const legacyResource = Reflect.get(credential, "resource");
	return typeof legacyResource === "string" && legacyResource.length > 0
		? legacyResource
		: undefined;
}

function oauthConfigFromStoredCredentials(
	secret: StoredCredentials | undefined,
	resource: string | null | undefined,
): OAuthResolvedConfig | null {
	const stored = secret?.oauth;
	const clientId = stringValue(stored?.clientId);
	if (!clientId) {
		return null;
	}

	const resolvedResource = stringValue(stored?.resource) ?? stringValue(resource);
	if (!resolvedResource) {
		return null;
	}

	return {
		issuer: stringValue(stored?.issuer),
		authorizationUrl: stringValue(stored?.authorizationUrl),
		tokenUrl: stringValue(stored?.tokenUrl),
		revocationUrl: stringValue(stored?.revocationUrl),
		clientId,
		clientSecret: stringValue(stored?.clientSecret),
		clientAuthentication: normalizeClientAuthentication(
			stringValue(stored?.clientAuthentication),
			Boolean(stored?.clientSecret),
		),
		scopes: stringValue(stored?.scopes),
		resource: normalizeResource(resolvedResource),
	};
}

function shouldRefresh(
	secret: StoredCredentials | undefined,
	clock: () => Date,
	force = false,
) {
	if (force) {
		return true;
	}
	const expiresAt = secret?.oauth?.expiresAt;
	if (!expiresAt) {
		return false;
	}
	const parsed = new Date(expiresAt);
	if (Number.isNaN(parsed.getTime())) {
		return false;
	}
	return parsed.getTime() <= clock().getTime() + 60_000;
}

function oauthSecretFromTokenResponse(
	response: oauth.TokenEndpointResponse,
	oauthConfig: OAuthResolvedConfig,
	existing?: StoredCredentials,
): StoredCredentials & { headers: Record<string, string> } {
	const accessToken = response.access_token;
	const refreshToken =
		response.refresh_token ?? existing?.oauth?.refreshToken ?? null;
	const expiresAt =
		typeof response.expires_in === "number"
			? new Date(Date.now() + response.expires_in * 1000).toISOString()
			: existing?.oauth?.expiresAt;

	return {
		headers: buildCredentialHeaders(
			{ type: "http", scheme: "bearer" },
			accessToken,
		),
		oauth: {
			accessToken,
			refreshToken,
			expiresAt,
			scopes:
				typeof response.scope === "string"
					? response.scope
					: existing?.oauth?.scopes,
			tokenType: response.token_type,
			resource: oauthConfig.resource,
			issuer: oauthConfig.issuer,
			authorizationUrl: oauthConfig.authorizationUrl,
			tokenUrl: oauthConfig.tokenUrl,
			revocationUrl: oauthConfig.revocationUrl,
			clientId: oauthConfig.clientId,
			clientSecret: oauthConfig.clientSecret,
			clientAuthentication: oauthConfig.clientAuthentication,
		},
	};
}

const AUTH_HEADER_NAMES = new Set(["authorization", "proxy-authorization"]);

function mergeHeaders(
	existing: Record<string, string> | undefined,
	next: Record<string, string>,
	mode: ConnectCompleteInput["merge"],
) {
	if (mode !== "preserve-non-auth-headers" || !existing) {
		return next;
	}

	const merged: Record<string, string> = {};
	for (const [name, value] of Object.entries(existing)) {
		if (!AUTH_HEADER_NAMES.has(name.toLowerCase())) {
			merged[name] = value;
		}
	}
	return {
		...merged,
		...next,
	};
}

async function resolveAuthorizationServer(
	config: OAuthResolvedConfig,
	customFetch: typeof fetch | undefined,
) {
	if (config.issuer) {
		const issuer = assertUrl(config.issuer, "oauth issuer");
		const authorizationServer = await discoverAuthorizationServerMetadata(
			issuer,
			customFetch,
		);
		if (!authorizationServer) {
			throw new AgentPwInputError(
				`Authorization server '${config.issuer}' does not publish usable metadata`,
			);
		}
		return authorizationServer;
	}

	if (!(config.authorizationUrl && config.tokenUrl)) {
		throw new AgentPwInputError(
			"OAuth configuration requires either issuer or authorizationUrl + tokenUrl",
		);
	}

	return {
		issuer: new URL(config.authorizationUrl).origin,
		authorization_endpoint: config.authorizationUrl,
		token_endpoint: config.tokenUrl,
		revocation_endpoint: config.revocationUrl,
	} satisfies oauth.AuthorizationServer;
}

type AuthorizationServerDiscoveryAttempt = {
	url: URL;
	request(): Promise<Response>;
};

function buildAuthorizationServerDiscoveryAttempts(
	issuer: URL,
	customFetch: typeof fetch | undefined,
) {
	const pathname =
		issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
	const discoveryOptions = customFetch
		? { [oauth.customFetch]: customFetch }
		: undefined;
	const attempts: AuthorizationServerDiscoveryAttempt[] = [
		{
			url: pathname
				? new URL(
						`/.well-known/oauth-authorization-server${pathname}`,
						issuer.origin,
					)
				: new URL("/.well-known/oauth-authorization-server", issuer.origin),
			request: () =>
				oauth.discoveryRequest(issuer, {
					...discoveryOptions,
					algorithm: "oauth2",
				}),
		},
	];

	if (pathname) {
		const oidcInsertedUrl = new URL(
			`/.well-known/openid-configuration${pathname}`,
			issuer.origin,
		);
		attempts.push({
			url: oidcInsertedUrl,
			request: () =>
				(customFetch ?? fetch)(oidcInsertedUrl, {
					headers: {
						Accept: "application/json",
					},
				}),
		});
	}

	attempts.push({
		url: pathname
			? new URL(`${pathname}/.well-known/openid-configuration`, issuer.origin)
			: new URL("/.well-known/openid-configuration", issuer.origin),
		request: () =>
			oauth.discoveryRequest(issuer, {
				...discoveryOptions,
				algorithm: "oidc",
			}),
	});

	return attempts;
}

async function discoverAuthorizationServerMetadata(
	issuer: URL,
	customFetch: typeof fetch | undefined,
) {
	for (const attempt of buildAuthorizationServerDiscoveryAttempts(
		issuer,
		customFetch,
	)) {
		const response = await attempt.request();

		if (!response.ok) {
			if (response.status >= 400 && response.status < 500) {
				await response.body?.cancel();
				continue;
			}
			throw new AgentPwInputError(
				`Authorization server discovery failed for '${issuer.toString()}' at '${attempt.url.toString()}' with HTTP ${response.status}`,
			);
		}

		return oauth.processDiscoveryResponse(issuer, response);
	}

	return null;
}

async function discoverResource(
	resource: string,
	customFetch: typeof fetch | undefined,
) {
	const normalizedResource = normalizeResource(resource);
	const resourceUrl = assertUrl(normalizedResource, "resource");
	const metadataResponse = await oauth.resourceDiscoveryRequest(
		resourceUrl,
		customFetch ? { [oauth.customFetch]: customFetch } : undefined,
	);
	const resourceServer = await oauth.processResourceDiscoveryResponse(
		resourceUrl,
		metadataResponse,
	);
	return {
		resource: normalizedResource,
		authorizationServers: resourceServer.authorization_servers ?? [],
		resourceName: stringValue(resourceServer.resource_name),
		scopes: Array.isArray(resourceServer.scopes_supported)
			? resourceServer.scopes_supported.filter(
					(entry): entry is string => typeof entry === "string",
				)
			: [],
	};
}

function cimdToClientMetadata(
	input: NonNullable<OAuthClientInput["metadata"]>,
) {
	return {
		client_id: input.clientId,
		redirect_uris: input.redirectUris,
		client_name: input.clientName,
		scope: toScopeString(input.scope),
		grant_types: ["authorization_code", "refresh_token"],
		token_endpoint_auth_method: input.tokenEndpointAuthMethod,
		jwks_uri: input.jwksUri,
		jwks: input.jwks ? JSON.parse(JSON.stringify(input.jwks)) : undefined,
		token_endpoint_auth_signing_alg: input.tokenEndpointAuthSigningAlg,
	} satisfies Partial<oauth.Client>;
}

function resolveRedirectUri(request: Request, callbackPath: string) {
	const url = new URL(request.url);
	const callbackUrl = new URL(callbackPath, url);
	return callbackUrl.toString();
}

function defaultSuccessResponse() {
	return new Response(
		"<!doctype html><html><body><p>Authorization complete. You can close this window.</p></body></html>",
		{
			status: 200,
			headers: {
				"content-type": "text/html; charset=utf-8",
			},
		},
	);
}

function defaultErrorResponse(error: unknown) {
	const message = error instanceof Error ? error.message : "OAuth flow failed";
	return new Response(JSON.stringify({ error: message }), {
		status: 400,
		headers: {
			"content-type": "application/json; charset=utf-8",
		},
	});
}

export function createInMemoryFlowStore(): FlowStore {
	const store = new Map<string, PendingFlow>();

	return {
		async create(flow) {
			store.set(flow.id, flow);
		},
		async get(id) {
			return store.get(id) ?? null;
		},
		async complete(id, _result?: CompletedFlowResult) {
			store.delete(id);
		},
		async delete(id) {
			store.delete(id);
		},
	};
}

function parseProfileOAuthConfig(
	profile: CredentialProfileRecord,
	resource: string,
	clientInput: OAuthClientInput | undefined,
): OAuthResolvedConfig {
	if (profile.auth.kind !== "oauth") {
		throw new AgentPwInputError(
			`Credential Profile '${profile.path}' is not an OAuth profile`,
		);
	}

	const clientId =
		profile.auth.clientId ??
		clientInput?.clientId ??
		clientInput?.metadata?.clientId;
	const clientSecret = profile.auth.clientSecret ?? clientInput?.clientSecret;
	const clientAuthentication = normalizeClientAuthentication(
		profile.auth.clientAuthentication ?? clientInput?.clientAuthentication,
		Boolean(clientSecret),
	);

	if (!clientId) {
		throw new AgentPwInputError(
			`Credential Profile '${profile.path}' requires a clientId or default oauth client`,
		);
	}

	return {
		issuer: profile.auth.issuer,
		authorizationUrl: profile.auth.authorizationUrl,
		tokenUrl: profile.auth.tokenUrl,
		revocationUrl: profile.auth.revocationUrl,
		clientId,
		clientSecret,
		clientAuthentication,
		scopes: profile.auth.scopes,
		resource: normalizeResource(resource),
	};
}

async function resolveOAuthConfigForResourceOption(
	option: ConnectOAuthOption,
	clientInput: OAuthClientInput | undefined,
	customFetch: typeof fetch | undefined,
) {
	const client = clientInput;
	if (!client) {
		throw new AgentPwInputError(
			`Resource '${option.resource}' requires oauth client configuration`,
		);
	}

	const discovered = await discoverResource(option.resource, customFetch);
	const issuer =
		option.authorizationServer ?? discovered.authorizationServers[0];
	if (!issuer) {
		throw new AgentPwInputError(
			`Resource '${option.resource}' does not advertise an authorization server`,
		);
	}

	if (
		option.authorizationServer &&
		!discovered.authorizationServers.includes(option.authorizationServer)
	) {
		throw new AgentPwInputError(
			`Authorization server '${option.authorizationServer}' is not advertised for resource '${option.resource}'`,
		);
	}

	const issuerUrl = assertUrl(issuer, "authorization server");
	const authorizationServer = await discoverAuthorizationServerMetadata(
		issuerUrl,
		customFetch,
	);
	if (!authorizationServer) {
		throw new AgentPwInputError(
			`Authorization server '${issuer}' does not publish usable metadata`,
		);
	}
	const shouldRegisterDynamically = Boolean(
		client.useDynamicRegistration || (!client.clientId && client.metadata),
	);
	let clientId = client.clientId ?? client.metadata?.clientId;
	let clientSecret = client.clientSecret;
	let clientAuthentication = normalizeClientAuthentication(
		client.clientAuthentication,
		Boolean(clientSecret),
	);

	if (shouldRegisterDynamically) {
		if (!client.metadata) {
			throw new AgentPwInputError(
				"Dynamic client registration requires client metadata",
			);
		}
		if (!authorizationServer.registration_endpoint) {
			throw new AgentPwInputError(
				`Authorization server '${authorizationServer.issuer}' does not support dynamic client registration`,
			);
		}

		const registrationResponse = await oauth.dynamicClientRegistrationRequest(
			authorizationServer,
			cimdToClientMetadata(client.metadata),
			{
				initialAccessToken: client.initialAccessToken,
				...(customFetch ? { [oauth.customFetch]: customFetch } : {}),
			},
		);
		const registered =
			await oauth.processDynamicClientRegistrationResponse(
				registrationResponse,
			);
		clientId = stringValue(registered.client_id);
		clientSecret = stringValue(registered.client_secret);
		clientAuthentication = normalizeClientAuthentication(
			stringValue(registered.token_endpoint_auth_method),
			Boolean(clientSecret),
		);
	}

	if (!clientId) {
		throw new AgentPwInputError(
			`Resource '${option.resource}' requires a clientId or dynamic client registration`,
		);
	}

	return {
		issuer: authorizationServer.issuer,
		authorizationUrl: authorizationServer.authorization_endpoint,
		tokenUrl: authorizationServer.token_endpoint,
		revocationUrl: authorizationServer.revocation_endpoint,
		clientId,
		clientSecret,
		clientAuthentication,
		scopes: option.scopes,
		resource: normalizeResource(option.resource),
	} satisfies OAuthResolvedConfig;
}

export function createOAuthService(options: {
	flowStore?: FlowStore;
	clock: () => Date;
	customFetch?: typeof fetch;
	defaultClient?: OAuthClientInput;
	getProfile(path: string): Promise<CredentialProfileRecord | null>;
	getCredential(path: string): Promise<CredentialRecord | null>;
	putCredential(input: CredentialPutInput): Promise<CredentialRecord>;
	deleteCredential(path: string): Promise<boolean>;
}) {
	async function requireFlowStore() {
		if (!options.flowStore) {
			throw new AgentPwInputError("OAuth flows require an explicit flowStore");
		}
		return options.flowStore;
	}

	async function resolveOAuthConfigForOption(
		option: ConnectOAuthOption,
		clientInput: OAuthClientInput | undefined,
	) {
		if (option.source === "profile") {
			if (!option.profilePath) {
				throw new AgentPwInputError(
					"Profile-backed OAuth option is missing profilePath",
				);
			}
			const profile = await options.getProfile(option.profilePath);
			if (!profile) {
				throw new AgentPwInputError(
					`Credential Profile '${option.profilePath}' does not exist`,
				);
			}
			return parseProfileOAuthConfig(
				profile,
				option.resource,
				clientInput ?? options.defaultClient,
			);
		}

		return resolveOAuthConfigForResourceOption(
			option,
			clientInput ?? options.defaultClient,
			options.customFetch,
		);
	}

	async function refreshCredential(
		path: string,
		optionsForRefresh: {
			force?: boolean;
		} = {},
	) {
		const credential = await options.getCredential(path);
		if (!credential) {
			return null;
		}

		if (credential.auth.kind !== "oauth") {
			return credential;
		}

		if (
			!shouldRefresh(credential.secret, options.clock, optionsForRefresh.force)
		) {
			return credential;
		}

		const refreshToken = credential.secret.oauth?.refreshToken;
		if (!refreshToken) {
			return credential;
		}

		const oauthConfig = oauthConfigFromStoredCredentials(
			credential.secret,
			resourceFromCredentialRecord(credential),
		);
		if (!oauthConfig) {
			return credential;
		}

		const authorizationServer = await resolveAuthorizationServer(
			oauthConfig,
			options.customFetch,
		);
		const client = buildClient(oauthConfig);
		const clientAuthentication = buildClientAuthentication(oauthConfig);
		const tokenResponse = await oauth.refreshTokenGrantRequest(
			authorizationServer,
			client,
			clientAuthentication,
			refreshToken,
			options.customFetch
				? { [oauth.customFetch]: options.customFetch }
				: undefined,
		);
		const processed = await oauth.processRefreshTokenResponse(
			authorizationServer,
			client,
			tokenResponse,
		);
		return options.putCredential({
			path: credential.path,
			auth: credential.auth,
			secret: oauthSecretFromTokenResponse(
				processed,
				oauthConfig,
				credential.secret,
			),
		});
	}

	return {
		async getFlow(id: string) {
			const flowStore = await requireFlowStore();
			return flowStore.get(id);
		},

		async discoverResource(input: { resource: string; response?: Response }) {
			return discoverResource(input.resource, options.customFetch);
		},

		async startAuthorization(
			input: ConnectStartInput,
		): Promise<ConnectAuthorizationSession> {
			const flowStore = await requireFlowStore();
			const path = assertPath(input.path, "path");
			const redirectUri = assertUrl(
				input.redirectUri,
				"redirect uri",
			).toString();
			const context = jsonObject(input.context, "OAuth context");
			const reason = normalizeStartReason(input.reason);
			const oauthConfig = await resolveOAuthConfigForOption(
				input.option,
				input.client,
			);
			const authorizationServer = await resolveAuthorizationServer(
				oauthConfig,
				options.customFetch,
			);
			if (!authorizationServer.authorization_endpoint) {
				throw new AgentPwInputError(
					`OAuth option for '${input.option.resource}' is missing an authorization endpoint`,
				);
			}

			const flowId = validateFlowId(undefined) ?? randomId() + randomId();
			const codeVerifier = oauth.generateRandomCodeVerifier();
			const codeChallenge =
				await oauth.calculatePKCECodeChallenge(codeVerifier);
			const authorizationUrl = new URL(
				authorizationServer.authorization_endpoint,
			);

			authorizationUrl.searchParams.set("client_id", oauthConfig.clientId);
			authorizationUrl.searchParams.set("redirect_uri", redirectUri);
			authorizationUrl.searchParams.set("response_type", "code");
			authorizationUrl.searchParams.set("state", flowId);
			authorizationUrl.searchParams.set("code_challenge", codeChallenge);
			authorizationUrl.searchParams.set("code_challenge_method", "S256");
			authorizationUrl.searchParams.set("resource", oauthConfig.resource);

			const scopes =
				toScopeString(input.scopes) ?? toScopeString(oauthConfig.scopes);
			if (scopes) {
				authorizationUrl.searchParams.set("scope", scopes);
			}

			for (const [key, value] of Object.entries(
				input.additionalParameters ?? {},
			)) {
				authorizationUrl.searchParams.set(key, value);
			}

			const flow: PendingFlow = {
				id: flowId,
				path,
				resource: normalizeResource(input.option.resource),
				option: input.option,
				redirectUri,
				codeVerifier,
				expiresAt: input.expiresAt ?? defaultExpiry(options.clock),
				oauthConfig,
				context,
				reason,
				requiresUpstreamAuthorization: reason === "auth_required",
			};
			await flowStore.create(flow);

			return {
				flowId,
				authorizationUrl: authorizationUrl.toString(),
				expiresAt: flow.expiresAt,
				path: flow.path,
				resource: flow.resource,
				option: flow.option,
				context: flow.context,
				reason: flow.reason,
				requiresUpstreamAuthorization: flow.requiresUpstreamAuthorization,
			};
		},

		async completeAuthorization(
			input: ConnectCompleteInput,
		): Promise<ConnectCompleteResult> {
			const flowStore = await requireFlowStore();
			const callbackUrl = assertUrl(input.callbackUri, "callback uri");
			const flowId = callbackUrl.searchParams.get("state");
			if (!flowId) {
				throw new AgentPwInputError("OAuth callback is missing state");
			}

			const flow = await flowStore.get(flowId);
			if (!flow) {
				throw new AgentPwInputError(`Unknown OAuth flow '${flowId}'`);
			}
			if (flow.expiresAt.getTime() <= options.clock().getTime()) {
				await flowStore.delete(flow.id);
				throw new AgentPwInputError(`OAuth flow '${flow.id}' has expired`);
			}

			const authorizationServer = await resolveAuthorizationServer(
				flow.oauthConfig,
				options.customFetch,
			);
			const client = buildClient(flow.oauthConfig);
			const clientAuthentication = buildClientAuthentication(flow.oauthConfig);
			const validated = oauth.validateAuthResponse(
				authorizationServer,
				client,
				callbackUrl,
				flow.id,
			);
			const tokenResponse = await oauth.authorizationCodeGrantRequest(
				authorizationServer,
				client,
				clientAuthentication,
				validated,
				flow.redirectUri,
				flow.codeVerifier,
				options.customFetch
					? { [oauth.customFetch]: options.customFetch }
					: undefined,
			);
			const processed = await oauth.processAuthorizationCodeResponse(
				authorizationServer,
				client,
				tokenResponse,
			);
			const existing =
				input.merge === "preserve-non-auth-headers"
					? await options.getCredential(flow.path)
					: null;
			const secret = oauthSecretFromTokenResponse(processed, flow.oauthConfig);
			secret.headers = mergeHeaders(
				existing?.secret.headers,
				secret.headers,
				input.merge,
			);

			const credential = await options.putCredential({
				path: flow.path,
				auth: {
					kind: "oauth",
					profilePath: flow.option.profilePath ?? null,
					label: flow.option.label,
					resource: flow.resource,
				},
				secret,
			});

			await flowStore.complete(flow.id, {
				context: flow.context,
				reason: flow.reason,
				requiresUpstreamAuthorization: flow.requiresUpstreamAuthorization,
			});

			return {
				path: flow.path,
				credential,
				context: flow.context,
				outcome: "connected",
				reason: flow.reason,
				requiresUpstreamAuthorization: flow.requiresUpstreamAuthorization,
			};
		},

		async refreshCredential(path: string, force = false) {
			return refreshCredential(assertPath(path, "path"), { force });
		},

		async disconnect(input: ConnectDisconnectInput) {
			const path = assertPath(input.path, "path");
			const credential = await options.getCredential(path);
			if (!credential) {
				return false;
			}

			if (credential.auth.kind === "oauth") {
				const oauthConfig = oauthConfigFromStoredCredentials(
					credential.secret,
					resourceFromCredentialRecord(credential),
				);
				const revokeMode = input.revoke ?? "refresh_token";
				if (oauthConfig) {
					const authorizationServer = await resolveAuthorizationServer(
						oauthConfig,
						options.customFetch,
					);
					if (authorizationServer.revocation_endpoint) {
						const client = buildClient(oauthConfig);
						const clientAuthentication = buildClientAuthentication(oauthConfig);

						if (
							(revokeMode === "refresh_token" || revokeMode === "both") &&
							credential.secret.oauth?.refreshToken
						) {
							const response = await oauth.revocationRequest(
								authorizationServer,
								client,
								clientAuthentication,
								credential.secret.oauth.refreshToken,
								options.customFetch
									? {
											[oauth.customFetch]: options.customFetch,
											additionalParameters: {
												token_type_hint: "refresh_token",
											},
										}
									: {
											additionalParameters: {
												token_type_hint: "refresh_token",
											},
										},
							);
							await oauth.processRevocationResponse(response);
						}

						if (
							(revokeMode === "access_token" || revokeMode === "both") &&
							credential.secret.oauth?.accessToken
						) {
							const response = await oauth.revocationRequest(
								authorizationServer,
								client,
								clientAuthentication,
								credential.secret.oauth.accessToken,
								options.customFetch
									? {
											[oauth.customFetch]: options.customFetch,
											additionalParameters: { token_type_hint: "access_token" },
										}
									: {
											additionalParameters: { token_type_hint: "access_token" },
										},
							);
							await oauth.processRevocationResponse(response);
						}
					}
				}
			}

			return options.deleteCredential(path);
		},

		createWebHandlers(
			optionsForHandlers: {
				callbackPath?: string;
				success?(
					result: ConnectCompleteResult,
					request: Request,
				): Response | Promise<Response>;
				error?(error: unknown, request: Request): Response | Promise<Response>;
			} = {},
		): ConnectWebHandlers {
			const callbackPath = optionsForHandlers.callbackPath ?? "/oauth/callback";

			return {
				start: async (request, input) => {
					const session = await this.startAuthorization({
						...input,
						path: assertPath(input.path, "path"),
						redirectUri:
							input.redirectUri ?? resolveRedirectUri(request, callbackPath),
					});
					return Response.redirect(session.authorizationUrl, 302);
				},

				callback: async (request) => {
					try {
						const result = await this.completeAuthorization({
							callbackUri: request.url,
						});
						if (optionsForHandlers.success) {
							return optionsForHandlers.success(result, request);
						}
						return defaultSuccessResponse();
					} catch (error) {
						if (optionsForHandlers.error) {
							return optionsForHandlers.error(error, request);
						}
						return defaultErrorResponse(error);
					}
				},
			};
		},

		createClientMetadataDocument(input: CimdDocumentInput): CimdDocument {
			const clientId = assertUrl(input.clientId, "client id").toString();
			if (input.redirectUris.length === 0) {
				throw new AgentPwInputError("CIMD requires at least one redirect URI");
			}

			return {
				client_id: clientId,
				redirect_uris: input.redirectUris.map((uri) =>
					assertUrl(uri, "redirect uri").toString(),
				),
				response_types: ["code"],
				grant_types: ["authorization_code", "refresh_token"],
				token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? "none",
				client_name: input.clientName,
				scope: toScopeString(input.scope),
				jwks_uri: input.jwksUri
					? assertUrl(input.jwksUri, "jwks uri").toString()
					: undefined,
				jwks: input.jwks,
				token_endpoint_auth_signing_alg: input.tokenEndpointAuthSigningAlg,
			};
		},

		createClientMetadataResponse(input: CimdDocumentInput) {
			return new Response(
				JSON.stringify(this.createClientMetadataDocument(input), null, 2),
				{
					status: 200,
					headers: {
						"content-type": "application/json; charset=utf-8",
						"cache-control": "public, max-age=300",
					},
				},
			);
		},
	};
}
