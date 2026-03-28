import { err, ok } from "okay-error";
import { createQueryHelpers } from "./db/queries.js";
import {
  authorizationError,
  conflictError,
  inputError,
  notFoundError,
} from "./errors.js";
import {
  decryptCredentials,
  encryptCredentials,
  type StoredCredentials,
} from "./lib/credentials-crypto.js";
import { mergeHeaders } from "./lib/connect-headers.js";
import { createLogger } from "./lib/logger.js";
import { isRecord } from "./lib/utils.js";
import { createOAuthService } from "./oauth.js";
import { assertOptionalPath, assertPath, credentialName, pathDepth } from "./paths.js";
import { normalizeResource } from "./resource-patterns.js";
import { authorizeRules, can as canRule } from "./rules.js";
import type {
  AgentPw,
  AgentPwOptions,
  ConnectFlow,
  ConnectOAuthOption,
  ConnectOption,
  ConnectPrepareInput,
  ConnectResolutionResult,
  CredentialAuth,
  CredentialProfileAuth,
  CredentialProfilePutInput,
  CredentialProfileRecord,
  CredentialRecord,
  CredentialSummary,
  PendingFlow,
  RuleScope,
  ScopedAgentPw,
} from "./types.js";

function resolveSingleMatch<T extends { path: string }>(matches: T[], description: string) {
  if (matches.length === 0) {
    return ok(undefined);
  }

  const topDepth = matches
    .map((match) => pathDepth(match.path))
    .reduce((max, depth) => Math.max(max, depth), 0);
  const conflicts = matches.filter((match) => pathDepth(match.path) === topDepth);
  if (conflicts.length > 1) {
    return err(
      conflictError(
        `${description} resolves to multiple candidates at the same depth: ${conflicts.map((conflict) => conflict.path).join(", ")}`,
      ),
    );
  }

  return ok(conflicts[0]);
}

function parseProfileAuth(value: unknown) {
  if (!isRecord(value)) {
    return err(inputError("Invalid profile auth payload"));
  }
  if (value.kind === "oauth") {
    return ok<CredentialProfileAuth>({
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
    });
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

    return ok<CredentialProfileAuth>({
      kind: "headers",
      label: typeof value.label === "string" ? value.label : undefined,
      fields,
    });
  }
  return err(inputError("Invalid profile auth kind"));
}

function parseCredentialAuth(value: unknown) {
  if (!isRecord(value) || (value.kind !== "oauth" && value.kind !== "headers")) {
    return err(inputError("Invalid credential auth payload"));
  }

  const resource =
    typeof value.resource === "string"
      ? normalizeResource(value.resource)
      : ok<string | null>(null);
  if (!resource.ok) {
    return resource;
  }

  const authBase = {
    profilePath: typeof value.profilePath === "string" ? value.profilePath : null,
    ...(resource.value ? { resource: resource.value } : {}),
  };
  if (value.kind === "oauth") {
    return ok<CredentialAuth>({
      kind: "oauth",
      ...authBase,
    });
  }
  return ok<CredentialAuth>({
    kind: "headers",
    ...authBase,
  });
}

function credentialResource(auth: CredentialAuth) {
  return typeof auth.resource === "string" ? auth.resource : null;
}

function normalizeCredentialAuth(auth: CredentialAuth, fallbackResource?: string) {
  const resource =
    typeof auth.resource === "string"
      ? auth.resource
      : typeof fallbackResource === "string"
        ? fallbackResource
        : null;
  return {
    ...auth,
    ...(resource ? { resource } : {}),
  };
}

function serializeCredentialAuth(auth: CredentialAuth) {
  return {
    kind: auth.kind,
    ...(auth.profilePath ? { profilePath: auth.profilePath } : {}),
    ...(auth.resource ? { resource: auth.resource } : {}),
  };
}

function requireHeadersSecret(secret: StoredCredentials, path: string) {
  if (!secret.headers || Object.keys(secret.headers).length === 0) {
    return err(inputError(`Credential '${path}' does not have header-based auth`, { path }));
  }
  return ok(secret.headers);
}

function requireOAuthSecret(secret: StoredCredentials, path: string) {
  if (!secret.headers || Object.keys(secret.headers).length === 0 || !secret.oauth) {
    return err(inputError(`Credential '${path}' does not have oauth auth`, { path }));
  }
  return ok(secret);
}

function validateSecretForAuth(auth: CredentialAuth, secret: StoredCredentials, path: string) {
  if (auth.kind === "oauth") {
    const oauth = requireOAuthSecret(secret, path);
    return oauth.ok ? ok() : oauth;
  }
  const headers = requireHeadersSecret(secret, path);
  return headers.ok ? ok() : headers;
}

function toJsonRecord(value: unknown) {
  const normalized = JSON.parse(JSON.stringify(value));
  if (!isRecord(normalized)) {
    return err(inputError("Expected JSON object"));
  }
  return ok(normalized);
}

function toProfileRecord(row: {
  path: string;
  resourcePatterns: string[];
  auth: Record<string, unknown>;
  displayName: string | null;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}) {
  const auth = parseProfileAuth(row.auth);
  if (!auth.ok) {
    return auth;
  }

  return ok<CredentialProfileRecord>({
    path: row.path,
    resourcePatterns: row.resourcePatterns,
    auth: auth.value,
    displayName: row.displayName,
    description: row.description,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
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
) {
  const auth = parseCredentialAuth(row.auth);
  if (!auth.ok) {
    return auth;
  }

  const resource = credentialResource(auth.value);
  const secret = await decryptCredentials(encryptionKey, row.secret);
  if (!secret.ok) {
    return secret;
  }

  return ok<CredentialRecord>({
    path: row.path,
    ...(resource ? { resource } : {}),
    auth: auth.value,
    secret: secret.value,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  });
}

function extractFlowId(callbackUri: string) {
  const url = new URL(callbackUri);
  return url.searchParams.get("state");
}

function parseHeaders(value: unknown) {
  if (!isRecord(value)) {
    return err(inputError("Expected headers object"));
  }

  const headers: Record<string, string> = {};
  for (const [name, entry] of Object.entries(value)) {
    if (typeof entry !== "string") {
      return err(inputError(`Invalid header value for '${name}'`, { field: name }));
    }
    headers[name] = entry;
  }
  return ok(headers);
}

function requireRule(scope: RuleScope, action: string, path: string) {
  const result = authorizeRules({
    rights: scope.rights,
    action,
    path,
  });

  if (!result.authorized) {
    return err(authorizationError(action, path, result.error));
  }
  return ok();
}

export async function createAgentPw(options: AgentPwOptions) {
  const logger = options.logger ?? createLogger("agentpw").logger;
  const encryptionKey = options.encryptionKey;
  const queries = createQueryHelpers(options.sql);
  if (!queries.ok) {
    return queries;
  }
  const queryHelpers = queries.value;

  const profiles: AgentPw["profiles"] = {
    async resolve(input, opts) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return err(path.error);
      }
      const resource = normalizeResource(input.resource);
      if (!resource.ok) {
        return resource;
      }

      const matches = await queryHelpers.getMatchingCredProfiles(
        opts?.db ?? options.db,
        path.value,
        resource.value,
      );
      if (!matches.ok) {
        return matches;
      }

      const selected = resolveSingleMatch(matches.value, "Credential Profile");
      if (!selected.ok) {
        return selected;
      }
      if (!selected.value) {
        return ok(null);
      }
      return toProfileRecord(selected.value);
    },

    async get(path, opts) {
      const normalizedPath = assertPath(path, "profile path");
      if (!normalizedPath.ok) {
        return err(normalizedPath.error);
      }
      const selected = await queryHelpers.getCredProfile(
        opts?.db ?? options.db,
        normalizedPath.value,
      );
      if (!selected.ok) {
        return selected;
      }
      if (!selected.value) {
        return ok(null);
      }
      return toProfileRecord(selected.value);
    },

    async list(query = {}) {
      const path = assertOptionalPath(query.path, "profile path");
      if (!path.ok) {
        return err(path.error);
      }
      const rows = await queryHelpers.listCredProfiles(query.db ?? options.db, {
        path: path.value,
        recursive: query.recursive,
      });
      if (!rows.ok) {
        return rows;
      }

      const records: CredentialProfileRecord[] = [];
      for (const row of rows.value) {
        const record = toProfileRecord(row);
        if (!record.ok) {
          return record;
        }
        records.push(record.value);
      }
      return ok(records);
    },

    async put(path, data: CredentialProfilePutInput, opts) {
      const db = opts?.db ?? options.db;
      const profilePath = assertPath(path, "profile path");
      if (!profilePath.ok) {
        return err(profilePath.error);
      }
      if (data.resourcePatterns.length === 0) {
        return err(inputError("Credential Profile resourcePatterns cannot be empty"));
      }

      const auth = toJsonRecord(data.auth);
      if (!auth.ok) {
        return auth;
      }
      const parsedAuth = parseProfileAuth(auth.value);
      if (!parsedAuth.ok) {
        return parsedAuth;
      }

      const persisted = await queryHelpers.upsertCredProfile(db, profilePath.value, {
        resourcePatterns: data.resourcePatterns,
        auth: parsedAuth.value as unknown as Record<string, unknown>,
        displayName: data.displayName,
        description: data.description,
      });
      if (!persisted.ok) {
        return persisted;
      }
      return toProfileRecord(persisted.value);
    },

    delete(path, opts) {
      const normalizedPath = assertPath(path, "profile path");
      if (!normalizedPath.ok) {
        return Promise.resolve(err(normalizedPath.error));
      }
      return queryHelpers.deleteCredProfile(opts?.db ?? options.db, normalizedPath.value, {
        recursive: opts?.recursive,
      });
    },
  };

  const getCredential: AgentPw["credentials"]["get"] = async (path, opts) => {
    const normalizedPath = assertPath(path, "credential path");
    if (!normalizedPath.ok) {
      return err(normalizedPath.error);
    }

    const selected = await queryHelpers.getCredential(opts?.db ?? options.db, normalizedPath.value);
    if (!selected.ok) {
      return selected;
    }
    if (!selected.value) {
      return ok(null);
    }
    return decryptCredentialRecord(encryptionKey, selected.value);
  };

  const putCredential: AgentPw["credentials"]["put"] = async (input, opts) => {
    const db = opts?.db ?? options.db;
    const path = assertPath(input.path, "credential path");
    if (!path.ok) {
      return err(path.error);
    }

    const authRecord = toJsonRecord(input.auth);
    if (!authRecord.ok) {
      return authRecord;
    }

    const parsedAuth = parseCredentialAuth(authRecord.value);
    if (!parsedAuth.ok) {
      return parsedAuth;
    }

    const parsedResource =
      typeof input.resource === "string"
        ? normalizeResource(input.resource)
        : ok<string | null>(null);
    if (!parsedResource.ok) {
      return parsedResource;
    }

    const existingResource = credentialResource(parsedAuth.value);
    const auth = normalizeCredentialAuth(
      parsedAuth.value,
      parsedResource.value && !existingResource ? parsedResource.value : undefined,
    );
    const plaintextSecret = Buffer.isBuffer(input.secret) ? undefined : input.secret;
    if (plaintextSecret) {
      const validSecret = validateSecretForAuth(auth, plaintextSecret, path.value);
      if (!validSecret.ok) {
        return validSecret;
      }
    }
    const encryptedSecret = Buffer.isBuffer(input.secret)
      ? ok(input.secret)
      : await encryptCredentials(encryptionKey, input.secret);
    if (!encryptedSecret.ok) {
      return encryptedSecret;
    }

    const persisted = await queryHelpers.upsertCredential(db, {
      path: path.value,
      auth: serializeCredentialAuth(auth),
      secret: encryptedSecret.value,
    });
    if (!persisted.ok) {
      return persisted;
    }

    return decryptCredentialRecord(encryptionKey, persisted.value);
  };

  function optionFromProfile(profile: CredentialProfileRecord, resource: string): ConnectOption {
    if (profile.auth.kind === "oauth") {
      return {
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
      };
    }

    return {
      kind: "headers",
      source: "profile",
      resource,
      profilePath: profile.path,
      label: profile.displayName ?? profile.auth.label ?? credentialName(profile.path),
      fields: profile.auth.fields,
    };
  }

  function toConnectFlow(flow: PendingFlow): ConnectFlow {
    return {
      flowId: flow.id,
      path: flow.path,
      resource: flow.oauthConfig.resource,
      ...(flow.credential.profilePath ? { profilePath: flow.credential.profilePath } : {}),
      expiresAt: flow.expiresAt,
    };
  }

  async function resolveConnection(input: ConnectPrepareInput) {
    const path = assertPath(input.path, "path");
    if (!path.ok) {
      return err(path.error);
    }
    const resource = normalizeResource(input.resource);
    if (!resource.ok) {
      return resource;
    }
    const existing = await getCredential(path.value);
    if (!existing.ok) {
      return existing;
    }

    if (existing.value) {
      const existingResource = credentialResource(existing.value.auth);
      if (existingResource && existingResource !== resource.value) {
        return err(
          conflictError(
            `Credential '${path.value}' is already connected to '${existingResource}', not '${resource.value}'`,
            { path: path.value },
          ),
        );
      }

      return ok({
        path: path.value,
        resource: resource.value,
        existing: existing.value,
        resolution: {
          canonicalResource: resource.value,
          source: null,
          reason: "existing-credential",
          profilePath: existing.value.auth.profilePath ?? null,
          option: null,
        } satisfies ConnectResolutionResult,
        options: [],
      });
    }

    const profile = await profiles.resolve({ path: path.value, resource: resource.value });
    if (!profile.ok) {
      return profile;
    }
    if (profile.value) {
      const option = optionFromProfile(profile.value, resource.value);
      return ok({
        path: path.value,
        resource: resource.value,
        existing: null,
        resolution: {
          canonicalResource: resource.value,
          source: "profile",
          reason: "matched-profile",
          profilePath: profile.value.path,
          option,
        } satisfies ConnectResolutionResult,
        options: [option],
      });
    }

    const discovered = await oauth.discoverResource({
      resource: resource.value,
      response: input.response,
    });
    if (discovered.ok) {
      const options = discovered.value.authorizationServers.map(
        (authorizationServer): ConnectOAuthOption => {
          const issuerHost = new URL(authorizationServer).host;
          return {
            kind: "oauth",
            source: "discovery",
            resource: resource.value,
            authorizationServer,
            label: discovered.value.resourceName
              ? `${discovered.value.resourceName} via ${issuerHost}`
              : `OAuth via ${issuerHost}`,
            scopes: discovered.value.scopes,
          };
        },
      );

      if (options.length > 0) {
        return ok({
          path: path.value,
          resource: resource.value,
          existing: null,
          resolution: {
            canonicalResource: resource.value,
            source: "discovery",
            reason: "discovered-oauth",
            profilePath: null,
            option: options[0],
          } satisfies ConnectResolutionResult,
          options,
        });
      }
    }

    return ok({
      path: path.value,
      resource: resource.value,
      existing: null,
      resolution: {
        canonicalResource: resource.value,
        source: null,
        reason: "unconfigured",
        profilePath: null,
        option: null,
      } satisfies ConnectResolutionResult,
      options: [],
    });
  }

  const oauth = createOAuthService({
    flowStore: options.flowStore,
    clock: options.clock ?? (() => new Date()),
    customFetch: options.oauthFetch,
    defaultClient: options.oauthClient,
    getProfile(path, opts) {
      return profiles.get(path, opts);
    },
    getCredential,
    putCredential,
    deleteCredential(path) {
      return queryHelpers.deleteCredential(options.db, path);
    },
  });

  const credentials: AgentPw["credentials"] = {
    get: getCredential,

    async list(query = {}) {
      const path = assertOptionalPath(query.path, "credential path");
      if (!path.ok) {
        return err(path.error);
      }
      const rows = await queryHelpers.listCredentials(query.db ?? options.db, {
        path: path.value,
        recursive: query.recursive,
      });
      if (!rows.ok) {
        return rows;
      }

      const items: CredentialSummary[] = [];
      for (const row of rows.value) {
        const auth = parseCredentialAuth(row.auth);
        if (!auth.ok) {
          return auth;
        }
        items.push({
          path: row.path,
          auth: auth.value,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        });
      }
      return ok(items);
    },

    put(input, opts) {
      return putCredential(input, opts);
    },

    move(fromPath, toPath, opts) {
      const normalizedFrom = assertPath(fromPath, "source path");
      if (!normalizedFrom.ok) {
        return Promise.resolve(err(normalizedFrom.error));
      }
      const normalizedTo = assertPath(toPath, "target path");
      if (!normalizedTo.ok) {
        return Promise.resolve(err(normalizedTo.error));
      }
      return queryHelpers.moveCredential(
        opts?.db ?? options.db,
        normalizedFrom.value,
        normalizedTo.value,
      );
    },

    delete(path, opts) {
      const normalizedPath = assertPath(path, "credential path");
      if (!normalizedPath.ok) {
        return Promise.resolve(err(normalizedPath.error));
      }
      return queryHelpers.deleteCredential(opts?.db ?? options.db, normalizedPath.value, {
        recursive: opts?.recursive,
      });
    },
  };

  const connect: AgentPw["connect"] = {
    async prepare(input) {
      const resolved = await resolveConnection(input);
      if (!resolved.ok) {
        return resolved;
      }
      if (resolved.value.existing) {
        const credential =
          resolved.value.existing.auth.kind === "oauth"
            ? await oauth.refreshCredential(resolved.value.path, false, resolved.value.existing)
            : ok(resolved.value.existing);
        if (!credential.ok) {
          return credential;
        }
        const headers = requireHeadersSecret(
          (credential.value ?? resolved.value.existing).secret,
          (credential.value ?? resolved.value.existing).path,
        );
        if (!headers.ok) {
          return headers;
        }
        return ok({
          kind: "ready",
          credential: credential.value ?? resolved.value.existing,
          headers: headers.value,
          resolution: resolved.value.resolution,
        });
      }

      return ok({
        kind: "options",
        options: resolved.value.options,
        resolution: resolved.value.resolution,
      });
    },

    async getFlow(flowId) {
      const flow = await oauth.getFlow(flowId);
      if (!flow.ok) {
        return flow;
      }
      return ok(toConnectFlow(flow.value));
    },

    startOAuth(input) {
      if (input.option.kind !== "oauth") {
        return Promise.resolve(err(inputError("connect.startOAuth requires an oauth option")));
      }
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return Promise.resolve(err(path.error));
      }
      const headers =
        typeof input.headers === "undefined"
          ? ok<Record<string, string> | undefined>(undefined)
          : parseHeaders(input.headers);
      if (!headers.ok) {
        return Promise.resolve(headers);
      }
      return oauth.startAuthorization({
        ...input,
        path: path.value,
        ...(headers.value ? { headers: headers.value } : {}),
      });
    },

    completeOAuth(input, opts) {
      return oauth.completeAuthorization(input, opts);
    },

    async setHeaders(input, opts) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return err(path.error);
      }

      const headers = parseHeaders(input.headers);
      if (!headers.ok) {
        return headers;
      }

      const existing = await getCredential(path.value, opts);
      if (!existing.ok) {
        return existing;
      }

      if (!existing.value) {
        if (typeof input.resource !== "string") {
          return err(inputError("connect.setHeaders requires resource when creating a credential"));
        }

        const resource = normalizeResource(input.resource);
        if (!resource.ok) {
          return resource;
        }

        const profile = await profiles.resolve(
          {
            path: path.value,
            resource: resource.value,
          },
          opts,
        );
        if (!profile.ok) {
          return profile;
        }

        const selectedOption = profile.value
          ? optionFromProfile(profile.value, resource.value)
          : null;
        if (selectedOption?.kind === "oauth") {
          return err(
            inputError(`Resource '${resource.value}' requires OAuth; use connect.startOAuth(...)`),
          );
        }

        return putCredential(
          {
            path: path.value,
            auth: {
              kind: "headers",
              ...(selectedOption?.kind === "headers" && selectedOption.profilePath
                ? { profilePath: selectedOption.profilePath }
                : {}),
              resource: resource.value,
            },
            secret: {
              headers: headers.value,
            },
          },
          opts,
        );
      }

      if (existing.value.auth.kind === "oauth") {
        const secret = requireOAuthSecret(existing.value.secret, existing.value.path);
        if (!secret.ok) {
          return secret;
        }

        return putCredential(
          {
            path: path.value,
            auth: {
              kind: "oauth",
              profilePath: existing.value.auth.profilePath ?? undefined,
              resource: existing.value.auth.resource ?? undefined,
            },
            secret: {
              ...secret.value,
              headers: mergeHeaders({
                headers: headers.value,
                oauthHeaders: secret.value.headers,
              }),
            },
          },
          opts,
        );
      }

      const secret = requireHeadersSecret(existing.value.secret, existing.value.path);
      if (!secret.ok) {
        return secret;
      }

      return putCredential(
        {
          path: path.value,
          auth: {
            kind: "headers",
            profilePath: existing.value.auth.profilePath ?? undefined,
            resource: existing.value.auth.resource ?? undefined,
          },
          secret: {
            headers: mergeHeaders({ headers: headers.value }),
          },
        },
        opts,
      );
    },

    async resolveHeaders(input) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return err(path.error);
      }
      const credential =
        input.refresh === false
          ? await getCredential(path.value)
          : await oauth.refreshCredential(path.value);

      if (!credential.ok) {
        return credential;
      }
      if (!credential.value) {
        return err(
          notFoundError("credential", `No credential exists at '${path.value}'`, {
            path: path.value,
          }),
        );
      }

      return requireHeadersSecret(credential.value.secret, credential.value.path);
    },

    disconnect(input) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return Promise.resolve(err(path.error));
      }
      return oauth.disconnect({
        path: path.value,
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
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.connect", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          const result = await connect.prepare(input);
          if (!result.ok) {
            return result;
          }
          if (result.value.kind === "ready") {
            const useRule = requireRule(scope, "credential.use", path.value);
            if (!useRule.ok) {
              return useRule;
            }
          }
          return result;
        },

        async getFlow(flowId) {
          const flow = await oauth.getFlow(flowId);
          if (!flow.ok) {
            return flow;
          }
          const allowed = requireRule(scope, "credential.connect", flow.value.path);
          if (!allowed.ok) {
            return allowed;
          }
          return ok(toConnectFlow(flow.value));
        },

        async startOAuth(input) {
          const path = assertPath(input.path, "path");
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.connect", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          return connect.startOAuth(input);
        },

        async completeOAuth(input, opts) {
          const flowId = extractFlowId(input.callbackUri);
          if (!flowId) {
            return err(inputError("OAuth callback is missing state"));
          }
          const flow = await oauth.getFlow(flowId);
          if (!flow.ok) {
            return flow;
          }
          const allowed = requireRule(scope, "credential.connect", flow.value.path);
          if (!allowed.ok) {
            return allowed;
          }
          return connect.completeOAuth(input, opts);
        },

        async setHeaders(input, opts) {
          const path = assertPath(input.path, "path");
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.connect", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          return connect.setHeaders(input, opts);
        },

        async resolveHeaders(input) {
          const path = assertPath(input.path, "path");
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.use", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          return connect.resolveHeaders(input);
        },

        async disconnect(input) {
          const path = assertPath(input.path, "path");
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.connect", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          return connect.disconnect(input);
        },
      },

      credentials: {
        async get(path, opts) {
          const normalizedPath = assertPath(path, "credential path");
          if (!normalizedPath.ok) {
            return err(normalizedPath.error);
          }
          const allowed = requireRule(scope, "credential.read", normalizedPath.value);
          if (!allowed.ok) {
            return allowed;
          }
          return credentials.get(normalizedPath.value, opts);
        },

        async list(query = {}) {
          const path = assertOptionalPath(query.path, "credential path");
          if (!path.ok) {
            return err(path.error);
          }
          const items = await credentials.list({
            path: path.value,
            recursive: query.recursive,
            db: query.db,
          });
          if (!items.ok) {
            return items;
          }
          return ok(
            items.value.filter((item) =>
              canRule({
                rights: scope.rights,
                action: "credential.read",
                path: item.path,
              }),
            ),
          );
        },

        async put(input, opts) {
          const path = assertPath(input.path, "credential path");
          if (!path.ok) {
            return err(path.error);
          }
          const allowed = requireRule(scope, "credential.manage", path.value);
          if (!allowed.ok) {
            return allowed;
          }
          return credentials.put(input, opts);
        },

        async move(fromPath, toPath, opts) {
          const normalizedFrom = assertPath(fromPath, "source path");
          const normalizedTo = assertPath(toPath, "target path");
          if (!normalizedFrom.ok) {
            return err(normalizedFrom.error);
          }
          if (!normalizedTo.ok) {
            return err(normalizedTo.error);
          }
          const fromAllowed = requireRule(scope, "credential.manage", normalizedFrom.value);
          if (!fromAllowed.ok) {
            return fromAllowed;
          }
          const toAllowed = requireRule(scope, "credential.manage", normalizedTo.value);
          if (!toAllowed.ok) {
            return toAllowed;
          }
          return credentials.move(normalizedFrom.value, normalizedTo.value, opts);
        },

        async delete(path, opts) {
          const normalizedPath = assertPath(path, "credential path");
          if (!normalizedPath.ok) {
            return err(normalizedPath.error);
          }
          const allowed = requireRule(scope, "credential.manage", normalizedPath.value);
          if (!allowed.ok) {
            return allowed;
          }
          return credentials.delete(normalizedPath.value, opts);
        },
      },

      profiles: {
        async get(path, opts) {
          const normalizedPath = assertPath(path, "profile path");
          if (!normalizedPath.ok) {
            return err(normalizedPath.error);
          }
          const allowed = requireRule(scope, "profile.read", normalizedPath.value);
          if (!allowed.ok) {
            return allowed;
          }
          return profiles.get(normalizedPath.value, opts);
        },

        async list(query = {}) {
          const path = assertOptionalPath(query.path, "profile path");
          if (!path.ok) {
            return err(path.error);
          }
          const items = await profiles.list({
            path: path.value,
            recursive: query.recursive,
            db: query.db,
          });
          if (!items.ok) {
            return items;
          }
          return ok(
            items.value.filter((item) =>
              canRule({
                rights: scope.rights,
                action: "profile.read",
                path: item.path,
              }),
            ),
          );
        },

        async put(path, data, opts) {
          const normalizedPath = assertPath(path, "profile path");
          if (!normalizedPath.ok) {
            return err(normalizedPath.error);
          }
          const allowed = requireRule(scope, "profile.manage", normalizedPath.value);
          if (!allowed.ok) {
            return allowed;
          }
          return profiles.put(normalizedPath.value, data, opts);
        },

        async delete(path, opts) {
          const normalizedPath = assertPath(path, "profile path");
          if (!normalizedPath.ok) {
            return err(normalizedPath.error);
          }
          const allowed = requireRule(scope, "profile.manage", normalizedPath.value);
          if (!allowed.ok) {
            return allowed;
          }
          return profiles.delete(normalizedPath.value, opts);
        },
      },
    };
  }

  function scope(input: RuleScope): ScopedAgentPw {
    return createScopedApi(input);
  }

  logger.debug("agent.pw initialized");

  return ok({
    profiles,
    credentials,
    connect,
    scope,
  });
}
export {
  ConnectFlowSchema,
  ConnectOAuthOptionSchema,
  LtreeLabelSchema,
  LtreePathSchema,
  OAuthResolvedConfigSchema,
  PendingFlowSchema,
} from "./types.js";
export type * from "./types.js";
