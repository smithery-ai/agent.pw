import { createQueryHelpers } from "./db/queries.js";
import {
	AgentPwAuthorizationError,
	AgentPwConflictError,
	AgentPwInputError,
} from "./errors.js";
import {
	decryptCredentials,
	encryptCredentials,
} from "./lib/credentials-crypto.js";
import { createLogger } from "./lib/logger.js";
import { isRecord } from "./lib/utils.js";
import { createOAuthService } from "./oauth.js";
import { canonicalizePath, credentialName, validatePath } from "./paths.js";
import { normalizeResource } from "./resource-patterns.js";
import { authorizeRules, can as canRule } from "./rules.js";
import type {
	AgentPw,
	AgentPwOptions,
	ConnectHeadersOption,
	ConnectOAuthOption,
	ConnectOption,
	ConnectPrepareInput,
	ConnectResolutionResult,
	CredentialAuth,
	CredentialProfileAuth,
	CredentialProfilePutInput,
	CredentialProfileRecord,
	CredentialPutInput,
	CredentialRecord,
	CredentialSummary,
	RuleScope,
	ScopedAgentPw,
} from "./types.js";

function assertPath(path: string, label: string) {
	const normalized = canonicalizePath(path);
	if (!validatePath(normalized) || normalized === "/") {
		throw new AgentPwInputError(`Invalid ${label} '${path}'`);
	}
	return normalized;
}

function assertListPath(path: string | undefined, label: string) {
	const normalized = canonicalizePath(path ?? "/");
	if (!validatePath(normalized)) {
		throw new AgentPwInputError(`Invalid ${label} '${path}'`);
	}
	return normalized;
}

function resolveSingleMatch<T extends { path: string }>(
	matches: T[],
	description: string,
): T | undefined {
	if (matches.length === 0) {
		return undefined;
	}

	const topDepth = matches
		.map((match) => match.path.split("/").filter(Boolean).length)
		.reduce((max, depth) => Math.max(max, depth), 0);
	const conflicts = matches.filter(
		(match) => match.path.split("/").filter(Boolean).length === topDepth,
	);
	if (conflicts.length > 1) {
		throw new AgentPwConflictError(
			`${description} resolves to multiple candidates at the same depth: ${conflicts.map((conflict) => conflict.path).join(", ")}`,
		);
	}

	return conflicts[0];
}

function parseProfileAuth(value: unknown): CredentialProfileAuth {
	if (!isRecord(value)) {
		throw new AgentPwInputError("Invalid profile auth payload");
	}
	if (value.kind === "oauth") {
		return {
			kind: "oauth",
			label: typeof value.label === "string" ? value.label : undefined,
			issuer: typeof value.issuer === "string" ? value.issuer : undefined,
			authorizationUrl:
				typeof value.authorizationUrl === "string"
					? value.authorizationUrl
					: undefined,
			tokenUrl: typeof value.tokenUrl === "string" ? value.tokenUrl : undefined,
			revocationUrl:
				typeof value.revocationUrl === "string"
					? value.revocationUrl
					: undefined,
			clientId: typeof value.clientId === "string" ? value.clientId : undefined,
			clientSecret:
				typeof value.clientSecret === "string" ? value.clientSecret : undefined,
			clientAuthentication:
				value.clientAuthentication === "client_secret_basic" ||
				value.clientAuthentication === "client_secret_post" ||
				value.clientAuthentication === "none"
					? value.clientAuthentication
					: undefined,
			scopes: Array.isArray(value.scopes)
				? value.scopes.filter(
						(entry): entry is string => typeof entry === "string",
					)
				: typeof value.scopes === "string"
					? value.scopes
					: undefined,
		};
	}
	if (value.kind === "headers") {
		const fields = Array.isArray(value.fields)
			? value.fields
					.filter(isRecord)
					.map((field) => ({
						name: typeof field.name === "string" ? field.name : "",
						label: typeof field.label === "string" ? field.label : "",
						description:
							typeof field.description === "string"
								? field.description
								: undefined,
						prefix: typeof field.prefix === "string" ? field.prefix : undefined,
						secret:
							typeof field.secret === "boolean" ? field.secret : undefined,
					}))
					.filter((field) => field.name.length > 0 && field.label.length > 0)
			: [];

		return {
			kind: "headers",
			label: typeof value.label === "string" ? value.label : undefined,
			fields,
		};
	}
	throw new AgentPwInputError("Invalid profile auth kind");
}

function parseCredentialAuth(value: unknown): CredentialAuth {
	if (
		!isRecord(value) ||
		(value.kind !== "oauth" && value.kind !== "headers")
	) {
		throw new AgentPwInputError("Invalid credential auth payload");
	}

	return {
		kind: value.kind,
		profilePath:
			typeof value.profilePath === "string" ? value.profilePath : null,
		label: typeof value.label === "string" ? value.label : null,
	};
}

function toJsonRecord(value: unknown) {
	const normalized = JSON.parse(JSON.stringify(value));
	if (!isRecord(normalized)) {
		throw new AgentPwInputError("Expected JSON object");
	}
	return normalized;
}

function toProfileRecord(row: {
	path: string;
	resourcePatterns: string[];
	auth: Record<string, unknown>;
	displayName: string | null;
	description: string | null;
	createdAt: Date;
	updatedAt: Date;
}): CredentialProfileRecord {
	return {
		path: row.path,
		resourcePatterns: row.resourcePatterns,
		auth: parseProfileAuth(row.auth),
		displayName: row.displayName,
		description: row.description,
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

async function decryptCredentialRecord(
	encryptionKey: string,
	row: {
		path: string;
		resource: string;
		auth: Record<string, unknown>;
		secret: Buffer;
		createdAt: Date;
		updatedAt: Date;
	},
): Promise<CredentialRecord> {
	return {
		path: row.path,
		resource: row.resource,
		auth: parseCredentialAuth(row.auth),
		secret: await decryptCredentials(encryptionKey, row.secret),
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

function extractFlowId(callbackUri: string) {
	const url = new URL(callbackUri);
	return url.searchParams.get("state");
}

function buildHeadersFromValues(
	option: ConnectHeadersOption,
	values: Record<string, string>,
) {
	const headers: Record<string, string> = {};

	for (const field of option.fields) {
		const value = values[field.name];
		if (typeof value !== "string" || value.length === 0) {
			throw new AgentPwInputError(`Missing header value for '${field.name}'`);
		}
		headers[field.name] = field.prefix ? `${field.prefix}${value}` : value;
	}

	return headers;
}

function requireRule(scope: RuleScope, action: string, path: string) {
	const result = authorizeRules({
		rights: scope.rights,
		action,
		path,
	});

	if (!result.authorized) {
		throw new AgentPwAuthorizationError(action, path, result.error);
	}
}

export async function createAgentPw(options: AgentPwOptions): Promise<AgentPw> {
	const logger = options.logger ?? createLogger("agentpw").logger;
	const encryptionKey = options.encryptionKey;
	const queries = createQueryHelpers(options.sql);

	const profiles: AgentPw["profiles"] = {
		async resolve(input) {
			const path = assertPath(input.path, "path");
			const resource = normalizeResource(input.resource);
			const matches = await queries.getMatchingCredProfiles(
				options.db,
				path,
				resource,
			);
			const selected = resolveSingleMatch(matches, "Credential Profile");
			return selected ? toProfileRecord(selected) : null;
		},

		async get(path) {
			const selected = await queries.getCredProfile(
				options.db,
				assertPath(path, "profile path"),
			);
			return selected ? toProfileRecord(selected) : null;
		},

		async list(query = {}) {
			const rows = await queries.listCredProfiles(options.db, {
				path: assertListPath(query.path, "profile path"),
			});
			return rows.map(toProfileRecord);
		},

		async put(path, data: CredentialProfilePutInput) {
			const profilePath = assertPath(path, "profile path");
			if (data.resourcePatterns.length === 0) {
				throw new AgentPwInputError(
					"Credential Profile resourcePatterns cannot be empty",
				);
			}

			await queries.upsertCredProfile(options.db, profilePath, {
				resourcePatterns: data.resourcePatterns,
				auth: toJsonRecord(data.auth),
				displayName: data.displayName,
				description: data.description,
			});

			const stored = await queries.getCredProfile(options.db, profilePath);
			if (!stored) {
				throw new Error(
					`Failed to persist Credential Profile '${profilePath}'`,
				);
			}
			return toProfileRecord(stored);
		},

		delete(path) {
			return queries.deleteCredProfile(
				options.db,
				assertPath(path, "profile path"),
			);
		},
	};

	async function getCredential(path: string) {
		const selected = await queries.getCredential(
			options.db,
			assertPath(path, "credential path"),
		);
		return selected ? decryptCredentialRecord(encryptionKey, selected) : null;
	}

	async function putCredential(input: CredentialPutInput) {
		const path = assertPath(input.path, "credential path");
		const resource = normalizeResource(input.resource);
		const secret = Buffer.isBuffer(input.secret)
			? input.secret
			: await encryptCredentials(encryptionKey, input.secret);

		await queries.upsertCredential(options.db, {
			path,
			resource,
			auth: toJsonRecord(input.auth),
			secret,
		});

		const stored = await queries.getCredential(options.db, path);
		if (!stored) {
			throw new Error(`Failed to persist Credential '${path}'`);
		}

		return decryptCredentialRecord(encryptionKey, stored);
	}

	function optionFromProfile(
		profile: CredentialProfileRecord,
		resource: string,
	): ConnectOption {
		if (profile.auth.kind === "oauth") {
			return {
				kind: "oauth",
				source: "profile",
				resource,
				profilePath: profile.path,
				label:
					profile.displayName ??
					profile.auth.label ??
					credentialName(profile.path),
				scopes: Array.isArray(profile.auth.scopes)
					? profile.auth.scopes
					: typeof profile.auth.scopes === "string"
						? profile.auth.scopes.split(/\s+/).filter(Boolean)
						: undefined,
			};
		}

		return {
			kind: "headers",
			source: "profile",
			resource,
			profilePath: profile.path,
			label:
				profile.displayName ??
				profile.auth.label ??
				credentialName(profile.path),
			fields: profile.auth.fields,
		};
	}

	async function resolveConnection(input: ConnectPrepareInput): Promise<{
		path: string;
		resource: string;
		existing: CredentialRecord | null;
		resolution: ConnectResolutionResult;
		options: ConnectOption[];
	}> {
		const path = assertPath(input.path, "path");
		const resource = normalizeResource(input.resource);
		const existing = await getCredential(path);

		if (existing) {
			if (existing.resource !== resource) {
				throw new AgentPwConflictError(
					`Credential '${path}' is already connected to '${existing.resource}', not '${resource}'`,
				);
			}

			return {
				path,
				resource,
				existing,
				resolution: {
					canonicalResource: resource,
					source: null,
					reason: "existing-credential",
					profilePath: existing.auth.profilePath ?? null,
					option: null,
				},
				options: [],
			};
		}

		const profile = await profiles.resolve({ path, resource });
		if (profile) {
			const option = optionFromProfile(profile, resource);
			return {
				path,
				resource,
				existing: null,
				resolution: {
					canonicalResource: resource,
					source: "profile",
					reason: "matched-profile",
					profilePath: profile.path,
					option,
				},
				options: [option],
			};
		}

		try {
			const discovered = await oauth.discoverResource({
				resource,
				response: input.response,
			});
			const options = discovered.authorizationServers.map(
				(authorizationServer): ConnectOAuthOption => {
					const issuerHost = new URL(authorizationServer).host;
					return {
						kind: "oauth",
						source: "discovery",
						resource,
						authorizationServer,
						label: discovered.resourceName
							? `${discovered.resourceName} via ${issuerHost}`
							: `OAuth via ${issuerHost}`,
						scopes: discovered.scopes,
					};
				},
			);

			if (options.length > 0) {
				return {
					path,
					resource,
					existing: null,
					resolution: {
						canonicalResource: resource,
						source: "discovery",
						reason: "discovered-oauth",
						profilePath: null,
						option: options[0],
					},
					options,
				};
			}
		} catch {
			// Discovery is optional. Unconfigured resources fall through below.
		}

		return {
			path,
			resource,
			existing: null,
			resolution: {
				canonicalResource: resource,
				source: null,
				reason: "unconfigured",
				profilePath: null,
				option: null,
			},
			options: [],
		};
	}

	const oauth = createOAuthService({
		flowStore: options.flowStore,
		clock: options.clock ?? (() => new Date()),
		customFetch: options.oauthFetch,
		defaultClient: options.oauthClient,
		getProfile(path) {
			return profiles.get(path);
		},
		getCredential,
		putCredential,
		deleteCredential(path) {
			return queries.deleteCredential(
				options.db,
				assertPath(path, "credential path"),
			);
		},
	});

	const credentials: AgentPw["credentials"] = {
		get: getCredential,

		async list(query = {}) {
			const rows = await queries.listCredentials(options.db, {
				path: assertListPath(query.path, "credential path"),
			});
			return rows.map<CredentialSummary>((row) => ({
				path: row.path,
				resource: row.resource,
				auth: parseCredentialAuth(row.auth),
				createdAt: row.createdAt,
				updatedAt: row.updatedAt,
			}));
		},

		put(input) {
			return putCredential(input);
		},

		move(fromPath, toPath) {
			return queries.moveCredential(
				options.db,
				assertPath(fromPath, "source path"),
				assertPath(toPath, "target path"),
			);
		},

		delete(path) {
			return queries.deleteCredential(
				options.db,
				assertPath(path, "credential path"),
			);
		},
	};

	const connect: AgentPw["connect"] = {
		async resolve(input) {
			const resolved = await resolveConnection(input);
			return resolved.resolution;
		},

		async prepare(input) {
			const resolved = await resolveConnection(input);
			if (resolved.existing) {
				const credential =
					resolved.existing.auth.kind === "oauth"
						? ((await oauth.refreshCredential(resolved.path)) ??
							resolved.existing)
						: resolved.existing;
				return {
					kind: "ready",
					credential,
					headers: credential.secret.headers,
				};
			}

			return {
				kind: "options",
				options: resolved.options,
			};
		},

		start(input) {
			if (input.option.kind !== "oauth") {
				throw new AgentPwInputError("connect.start requires an oauth option");
			}
			return oauth.startAuthorization({
				...input,
				path: assertPath(input.path, "path"),
			});
		},

		async startForResource(input) {
			const resolved = await resolveConnection(input);

			if (resolved.existing) {
				const credential =
					resolved.existing.auth.kind === "oauth"
						? ((await oauth.refreshCredential(resolved.path)) ??
							resolved.existing)
						: resolved.existing;
				return {
					kind: "ready",
					credential,
					headers: credential.secret.headers,
					resolution: resolved.resolution,
				};
			}

			const option = resolved.resolution.option;
			if (!option) {
				return {
					kind: "unconfigured",
					resolution: resolved.resolution,
				};
			}
			if (option.kind === "headers") {
				return {
					kind: "headers",
					option,
					resolution: resolved.resolution,
				};
			}

			const session = await oauth.startAuthorization({
				path: resolved.path,
				option,
				redirectUri: input.redirectUri,
				context: input.context,
				scopes: input.scopes,
				expiresAt: input.expiresAt,
				additionalParameters: input.additionalParameters,
				client: input.client,
			});

			return {
				kind: "authorization",
				resolution: resolved.resolution,
				...session,
			};
		},

		complete(input) {
			return oauth.completeAuthorization(input);
		},

		async saveHeaders(input) {
			const path = assertPath(input.path, "path");
			if (input.option.kind !== "headers") {
				throw new AgentPwInputError(
					"connect.saveHeaders requires a headers option",
				);
			}

			const headers = buildHeadersFromValues(input.option, input.values);
			return putCredential({
				path,
				resource: input.option.resource,
				auth: {
					kind: "headers",
					profilePath: input.option.profilePath ?? null,
					label: input.option.label,
				},
				secret: { headers },
			});
		},

		async headers(input) {
			const path = assertPath(input.path, "path");
			const credential =
				input.refresh === false
					? await getCredential(path)
					: await oauth.refreshCredential(path);

			if (!credential) {
				throw new AgentPwInputError(`No credential exists at '${path}'`);
			}

			return credential.secret.headers;
		},

		disconnect(input) {
			return oauth.disconnect({
				path: assertPath(input.path, "path"),
				revoke: input.revoke,
			});
		},

		createWebHandlers(optionsForHandlers) {
			return oauth.createWebHandlers(optionsForHandlers);
		},

		createClientMetadataDocument(input) {
			return oauth.createClientMetadataDocument(input);
		},

		createClientMetadataResponse(input) {
			return oauth.createClientMetadataResponse(input);
		},
	};

	function createScopedApi(scope: RuleScope): ScopedAgentPw {
		return {
			connect: {
				async resolve(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					const result = await connect.resolve(input);
					if (result.reason === "existing-credential") {
						requireRule(scope, "credential.use", path);
					}
					return result;
				},

				async prepare(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					const result = await connect.prepare(input);
					if (result.kind === "ready") {
						requireRule(scope, "credential.use", path);
					}
					return result;
				},

				async start(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					return connect.start(input);
				},

				async startForResource(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					const result = await connect.startForResource(input);
					if (result.kind === "ready") {
						requireRule(scope, "credential.use", path);
					}
					return result;
				},

				async complete(input) {
					const flowId = extractFlowId(input.callbackUri);
					if (!flowId) {
						throw new AgentPwInputError("OAuth callback is missing state");
					}
					const flow = await oauth.getFlow(flowId);
					if (!flow) {
						throw new AgentPwInputError(`Unknown OAuth flow '${flowId}'`);
					}
					requireRule(scope, "credential.connect", flow.path);
					return connect.complete(input);
				},

				async saveHeaders(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					return connect.saveHeaders(input);
				},

				async headers(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.use", path);
					return connect.headers(input);
				},

				async disconnect(input) {
					const path = assertPath(input.path, "path");
					requireRule(scope, "credential.connect", path);
					return connect.disconnect(input);
				},
			},

			credentials: {
				async get(path) {
					const normalizedPath = assertPath(path, "credential path");
					requireRule(scope, "credential.read", normalizedPath);
					return credentials.get(normalizedPath);
				},

				async list(query = {}) {
					const path = assertListPath(query.path, "credential path");
					const items = await credentials.list({ path });
					return items.filter((item) =>
						canRule({
							rights: scope.rights,
							action: "credential.read",
							path: item.path,
						}),
					);
				},

				async put(input) {
					const path = assertPath(input.path, "credential path");
					requireRule(scope, "credential.manage", path);
					return credentials.put(input);
				},

				async move(fromPath, toPath) {
					const normalizedFrom = assertPath(fromPath, "source path");
					const normalizedTo = assertPath(toPath, "target path");
					requireRule(scope, "credential.manage", normalizedFrom);
					requireRule(scope, "credential.manage", normalizedTo);
					return credentials.move(normalizedFrom, normalizedTo);
				},

				async delete(path) {
					const normalizedPath = assertPath(path, "credential path");
					requireRule(scope, "credential.manage", normalizedPath);
					return credentials.delete(normalizedPath);
				},
			},

			profiles: {
				async get(path) {
					const normalizedPath = assertPath(path, "profile path");
					requireRule(scope, "profile.read", normalizedPath);
					return profiles.get(normalizedPath);
				},

				async list(query = {}) {
					const path = assertListPath(query.path, "profile path");
					const items = await profiles.list({ path });
					return items.filter((item) =>
						canRule({
							rights: scope.rights,
							action: "profile.read",
							path: item.path,
						}),
					);
				},

				async put(path, data) {
					const normalizedPath = assertPath(path, "profile path");
					requireRule(scope, "profile.manage", normalizedPath);
					return profiles.put(normalizedPath, data);
				},

				async delete(path) {
					const normalizedPath = assertPath(path, "profile path");
					requireRule(scope, "profile.manage", normalizedPath);
					return profiles.delete(normalizedPath);
				},
			},
		};
	}

	function scope(input: RuleScope): ScopedAgentPw {
		return createScopedApi(input);
	}

	logger.debug("agent.pw initialized");

	return {
		profiles,
		credentials,
		connect,
		scope,
	};
}

export {
	AgentPwAuthorizationError,
	AgentPwConflictError,
	AgentPwInputError,
} from "./errors.js";
export type * from "./types.js";
