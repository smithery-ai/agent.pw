import { backfillCredentialResourcesToAuth } from "./db/legacy.js";
import { createQueryHelpers } from "./db/queries.js";
import { AgentPwAuthorizationError, AgentPwConflictError, AgentPwInputError } from "./errors.js";
import {
  decryptCredentials,
  encryptCredentials,
  type StoredCredentials,
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
  CredentialAuth,
  CredentialProfileAuth,
  CredentialProfilePutInput,
  CredentialProfileRecord,
  CredentialRecord,
  CredentialSummary,
  CredentialPutInput,
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
        typeof value.authorizationUrl === "string" ? value.authorizationUrl : undefined,
      tokenUrl: typeof value.tokenUrl === "string" ? value.tokenUrl : undefined,
      revocationUrl: typeof value.revocationUrl === "string" ? value.revocationUrl : undefined,
      clientId: typeof value.clientId === "string" ? value.clientId : undefined,
      clientSecret: typeof value.clientSecret === "string" ? value.clientSecret : undefined,
      clientAuthentication:
        value.clientAuthentication === "client_secret_basic" ||
        value.clientAuthentication === "client_secret_post" ||
        value.clientAuthentication === "none"
          ? value.clientAuthentication
          : undefined,
      scopes: Array.isArray(value.scopes)
        ? value.scopes.filter((entry): entry is string => typeof entry === "string")
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
            description: typeof field.description === "string" ? field.description : undefined,
            prefix: typeof field.prefix === "string" ? field.prefix : undefined,
            secret: typeof field.secret === "boolean" ? field.secret : undefined,
          }))
          .filter((field) => field.name.length > 0 && field.label.length > 0)
      : [];

    return {
      kind: "headers",
      label: typeof value.label === "string" ? value.label : undefined,
      fields,
    };
  }
  if (value.kind === "env") {
    const fields = Array.isArray(value.fields)
      ? value.fields
          .filter(isRecord)
          .map((field) => ({
            name: typeof field.name === "string" ? field.name : "",
            label: typeof field.label === "string" ? field.label : "",
            description: typeof field.description === "string" ? field.description : undefined,
            secret: typeof field.secret === "boolean" ? field.secret : undefined,
          }))
          .filter((field) => field.name.length > 0 && field.label.length > 0)
      : [];

    return {
      kind: "env",
      label: typeof value.label === "string" ? value.label : undefined,
      fields,
    };
  }
  throw new AgentPwInputError("Invalid profile auth kind");
}

function parseCredentialAuth(value: unknown): CredentialAuth {
  if (
    !isRecord(value) ||
    (value.kind !== "oauth" && value.kind !== "headers" && value.kind !== "env")
  ) {
    throw new AgentPwInputError("Invalid credential auth payload");
  }

  return {
    kind: value.kind,
    profilePath: typeof value.profilePath === "string" ? value.profilePath : null,
    label: typeof value.label === "string" ? value.label : null,
    resource: typeof value.resource === "string" ? normalizeResource(value.resource) : null,
  };
}

function credentialResource(auth: CredentialAuth) {
  return typeof auth.resource === "string" ? normalizeResource(auth.resource) : null;
}

function normalizeCredentialAuth(auth: CredentialAuth): CredentialAuth {
  return {
    ...auth,
    resource: credentialResource(auth),
  };
}

function requireHeadersSecret(secret: StoredCredentials, path: string) {
  if (!secret.headers || Object.keys(secret.headers).length === 0) {
    throw new AgentPwInputError(`Credential '${path}' does not have header-based auth`);
  }
  return secret.headers;
}

function requireEnvSecret(secret: StoredCredentials, path: string) {
  if (!secret.env || Object.keys(secret.env).length === 0) {
    throw new AgentPwInputError(`Credential '${path}' does not have env auth`);
  }
  return secret.env;
}

function validateSecretForAuth(auth: CredentialAuth, secret: StoredCredentials, path: string) {
  if (auth.kind === "env") {
    requireEnvSecret(secret, path);
    return;
  }
  requireHeadersSecret(secret, path);
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
    auth: Record<string, unknown>;
    secret: Buffer;
    createdAt: Date;
    updatedAt: Date;
  },
): Promise<CredentialRecord> {
  return {
    path: row.path,
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

function buildHeadersFromValues(option: ConnectHeadersOption, values: Record<string, string>) {
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

  await backfillCredentialResourcesToAuth(options.db, { sql: options.sql });

  const profiles: AgentPw["profiles"] = {
    async resolve(input) {
      const path = assertPath(input.path, "path");
      const resource = normalizeResource(input.resource);
      const matches = await queries.getMatchingCredProfiles(options.db, path, resource);
      const selected = resolveSingleMatch(matches, "Credential Profile");
      return selected ? toProfileRecord(selected) : null;
    },

    async get(path) {
      const selected = await queries.getCredProfile(options.db, assertPath(path, "profile path"));
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
        throw new AgentPwInputError("Credential Profile resourcePatterns cannot be empty");
      }

      await queries.upsertCredProfile(options.db, profilePath, {
        resourcePatterns: data.resourcePatterns,
        auth: toJsonRecord(data.auth),
        displayName: data.displayName,
        description: data.description,
      });

      const stored = await queries.getCredProfile(options.db, profilePath);
      if (!stored) {
        throw new Error(`Failed to persist Credential Profile '${profilePath}'`);
      }
      return toProfileRecord(stored);
    },

    delete(path) {
      return queries.deleteCredProfile(options.db, assertPath(path, "profile path"));
    },
  };

  async function getCredential(path: string) {
    const selected = await queries.getCredential(options.db, assertPath(path, "credential path"));
    return selected ? decryptCredentialRecord(encryptionKey, selected) : null;
  }

  async function putCredential(input: CredentialPutInput) {
    const path = assertPath(input.path, "credential path");
    const auth = normalizeCredentialAuth(parseCredentialAuth(toJsonRecord(input.auth)));
    const plaintextSecret = Buffer.isBuffer(input.secret) ? undefined : input.secret;
    if (plaintextSecret) {
      validateSecretForAuth(auth, plaintextSecret, path);
    }
    const secret = Buffer.isBuffer(input.secret)
      ? input.secret
      : await encryptCredentials(encryptionKey, input.secret);

    await queries.upsertCredential(options.db, {
      path,
      auth: toJsonRecord(auth),
      secret,
    });

    const stored = await queries.getCredential(options.db, path);
    if (!stored) {
      throw new Error(`Failed to persist Credential '${path}'`);
    }

    return decryptCredentialRecord(encryptionKey, stored);
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
      return queries.deleteCredential(options.db, assertPath(path, "credential path"));
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
      return queries.deleteCredential(options.db, assertPath(path, "credential path"));
    },
  };

  const connect: AgentPw["connect"] = {
    async prepare(input) {
      const path = assertPath(input.path, "path");
      const resource = normalizeResource(input.resource);
      const existing = await getCredential(path);

      if (existing) {
        if (existing.auth.kind === "env") {
          throw new AgentPwConflictError(
            `Credential '${path}' stores env auth and cannot be used with connect.prepare`,
          );
        }

        const existingResource = credentialResource(existing.auth);
        if (existingResource && existingResource !== resource) {
          throw new AgentPwConflictError(
            `Credential '${path}' is already connected to '${existingResource}', not '${resource}'`,
          );
        }
        const credential =
          existing.auth.kind === "oauth"
            ? ((await oauth.refreshCredential(path)) ?? existing)
            : existing;
        return {
          kind: "ready",
          credential,
          headers: requireHeadersSecret(credential.secret, credential.path),
        };
      }

      const optionsList: Array<ConnectOAuthOption | ConnectHeadersOption> = [];

      try {
        const discovered = await oauth.discoverResource({
          resource,
          response: input.response,
        });
        for (const authorizationServer of discovered.authorizationServers) {
          const issuerHost = new URL(authorizationServer).host;
          optionsList.push({
            kind: "oauth",
            source: "discovery",
            resource,
            authorizationServer,
            label: discovered.resourceName
              ? `${discovered.resourceName} via ${issuerHost}`
              : `OAuth via ${issuerHost}`,
            scopes: discovered.scopes,
          });
        }
      } catch {
        // Discovery is preferred but optional. Fallback profiles are checked next.
      }

      const profile = await profiles.resolve({ path, resource });
      if (profile) {
        if (profile.auth.kind === "oauth") {
          optionsList.push({
            kind: "oauth",
            source: "profile",
            resource,
            profilePath: profile.path,
            label: profile.displayName ?? profile.auth.label ?? credentialName(profile.path),
            scopes: Array.isArray(profile.auth.scopes)
              ? profile.auth.scopes
              : typeof profile.auth.scopes === "string"
                ? profile.auth.scopes.split(/\s+/).filter(Boolean)
                : undefined,
          });
        } else {
          optionsList.push({
            kind: "headers",
            source: "profile",
            resource,
            profilePath: profile.path,
            label: profile.displayName ?? profile.auth.label ?? credentialName(profile.path),
            fields: profile.auth.fields,
          });
        }
      }

      return {
        kind: "options",
        options: optionsList,
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

    complete(input) {
      return oauth.completeAuthorization(input);
    },

    async saveHeaders(input) {
      const path = assertPath(input.path, "path");
      if (input.option.kind !== "headers") {
        throw new AgentPwInputError("connect.saveHeaders requires a headers option");
      }

      const headers = buildHeadersFromValues(input.option, input.values);
      return putCredential({
        path,
        auth: {
          kind: "headers",
          profilePath: input.option.profilePath ?? null,
          label: input.option.label,
          resource: input.option.resource,
        },
        secret: { headers },
      });
    },

    async headers(input) {
      const path = assertPath(input.path, "path");
      const credential =
        input.refresh === false ? await getCredential(path) : await oauth.refreshCredential(path);

      if (!credential) {
        throw new AgentPwInputError(`No credential exists at '${path}'`);
      }
      if (credential.auth.kind === "env") {
        throw new AgentPwInputError(`Credential '${path}' stores env auth`);
      }

      return requireHeadersSecret(credential.secret, credential.path);
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

export type * from "./types.js";
export { AgentPwAuthorizationError, AgentPwConflictError, AgentPwInputError } from "./errors.js";
