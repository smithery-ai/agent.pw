import { err, ok, result } from "okay-error";
import * as oauth from "oauth4webapi";
import {
  expiredError,
  inputError,
  internalError,
  notFoundError,
  oauthError,
} from "./errors.js";
import { buildCredentialHeaders, type StoredCredentials } from "./lib/credentials-crypto.js";
import { isRecord, randomId, validateFlowId } from "./lib/utils.js";
import { normalizeResource } from "./resource-patterns.js";
import type {
  AgentPwError,
  AgentPwResult,
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

function assertPath(path: string, label: string): AgentPwResult<string> {
  if (!path.startsWith("/") || path === "/" || path.includes("..")) {
    return err(inputError(`Invalid ${label} '${path}'`, { field: label, value: path }));
  }
  return ok(path);
}

function assertUrl(value: string, label: string): AgentPwResult<URL> {
  const parsed = result(() => new URL(value));
  if (!parsed.ok) {
    return err(inputError(`Invalid ${label} '${value}'`, { field: label, value }));
  }
  return parsed;
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

function jsonObject(value: unknown, label: string): AgentPwResult<JsonObject | undefined> {
  if (value == null) {
    return ok(undefined);
  }
  const normalized = result(() => JSON.parse(JSON.stringify(value)));
  if (!normalized.ok || !isJsonObject(normalized.value)) {
    return err(inputError(`${label} must be a JSON object`, { field: label }));
  }
  return ok(normalized.value);
}

function toScopeString(value: string | string[] | undefined) {
  return Array.isArray(value) ? value.join(" ") : value;
}

function defaultExpiry(clock: () => Date) {
  return new Date(clock().getTime() + 10 * 60 * 1000);
}

function normalizeStartReason(value: ConnectStartInput["reason"]): PendingFlow["reason"] {
  return value === "auth_required" ? "auth_required" : "manual";
}

function normalizeClientAuthentication(
  value: string | undefined,
  hasSecret: boolean,
): OAuthClientAuthenticationMethod {
  if (value === "client_secret_basic" || value === "client_secret_post" || value === "none") {
    return value;
  }
  return hasSecret ? "client_secret_basic" : "none";
}

function buildClientAuthentication(
  config: OAuthResolvedConfig,
): AgentPwResult<ReturnType<typeof oauth.ClientSecretBasic>> {
  switch (config.clientAuthentication) {
    case "client_secret_post":
      if (!config.clientSecret) {
        return err(inputError("OAuth client_secret_post requires clientSecret"));
      }
      return ok(oauth.ClientSecretPost(config.clientSecret));
    case "client_secret_basic":
      if (!config.clientSecret) {
        return err(inputError("OAuth client_secret_basic requires clientSecret"));
      }
      return ok(oauth.ClientSecretBasic(config.clientSecret));
    case "none":
      return ok(oauth.None());
  }
}

function buildClient(config: OAuthResolvedConfig): oauth.Client {
  return {
    client_id: config.clientId,
  };
}

function resourceFromCredentialRecord(credential: CredentialRecord) {
  if (typeof credential.auth.resource === "string" && credential.auth.resource.length > 0) {
    return credential.auth.resource;
  }
  return undefined;
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

  const normalizedResource = normalizeResource(resolvedResource);
  if (!normalizedResource.ok) {
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
    resource: normalizedResource.value,
  };
}

function shouldRefresh(secret: StoredCredentials | undefined, clock: () => Date, force = false) {
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
  const refreshToken = response.refresh_token ?? existing?.oauth?.refreshToken ?? null;
  const expiresAt =
    typeof response.expires_in === "number"
      ? new Date(Date.now() + response.expires_in * 1000).toISOString()
      : existing?.oauth?.expiresAt;

  return {
    headers: buildCredentialHeaders({ type: "http", scheme: "bearer" }, accessToken),
    oauth: {
      accessToken,
      refreshToken,
      expiresAt,
      scopes: typeof response.scope === "string" ? response.scope : existing?.oauth?.scopes,
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
): Promise<AgentPwResult<oauth.AuthorizationServer>> {
  if (config.issuer) {
    const issuer = assertUrl(config.issuer, "oauth issuer");
    if (!issuer.ok) {
      return issuer;
    }
    const authorizationServer = await discoverAuthorizationServerMetadata(issuer.value, customFetch);
    if (!authorizationServer.ok) {
      return authorizationServer;
    }
    if (!authorizationServer.value) {
      return err(
        inputError(`Authorization server '${config.issuer}' does not publish usable metadata`),
      );
    }
    return ok(authorizationServer.value);
  }

  if (!(config.authorizationUrl && config.tokenUrl)) {
    return err(
      inputError("OAuth configuration requires either issuer or authorizationUrl + tokenUrl"),
    );
  }

  const authorizationOrigin = assertUrl(config.authorizationUrl, "authorization url");
  if (!authorizationOrigin.ok) {
    return authorizationOrigin;
  }

  return ok({
    issuer: authorizationOrigin.value.origin,
    authorization_endpoint: config.authorizationUrl,
    token_endpoint: config.tokenUrl,
    revocation_endpoint: config.revocationUrl,
  } satisfies oauth.AuthorizationServer);
}

type AuthorizationServerDiscoveryAttempt = {
  url: URL;
  request(): Promise<Response>;
};

function buildAuthorizationServerDiscoveryAttempts(
  issuer: URL,
  customFetch: typeof fetch | undefined,
) {
  const pathname = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  const discoveryOptions = customFetch ? { [oauth.customFetch]: customFetch } : undefined;
  const attempts: AuthorizationServerDiscoveryAttempt[] = [
    {
      url: pathname
        ? new URL(`/.well-known/oauth-authorization-server${pathname}`, issuer.origin)
        : new URL("/.well-known/oauth-authorization-server", issuer.origin),
      request: () =>
        oauth.discoveryRequest(issuer, {
          ...discoveryOptions,
          algorithm: "oauth2",
        }),
    },
  ];

  if (pathname) {
    const oidcInsertedUrl = new URL(`/.well-known/openid-configuration${pathname}`, issuer.origin);
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
): Promise<AgentPwResult<oauth.AuthorizationServer | null>> {
  for (const attempt of buildAuthorizationServerDiscoveryAttempts(issuer, customFetch)) {
    const response = await result(attempt.request());
    if (!response.ok) {
      return err(
        oauthError(
          "authorization-server-discovery",
          `Authorization server discovery failed for '${issuer.toString()}' at '${attempt.url.toString()}'`,
          { cause: response.error },
        ),
      );
    }

    if (!response.value.ok) {
      if (response.value.status >= 400 && response.value.status < 500) {
        await response.value.body?.cancel();
        continue;
      }
      return err(
        oauthError(
          "authorization-server-discovery",
          `Authorization server discovery failed for '${issuer.toString()}' at '${attempt.url.toString()}' with HTTP ${response.value.status}`,
        ),
      );
    }

    const processed = await result(oauth.processDiscoveryResponse(issuer, response.value));
    if (!processed.ok) {
      return err(
        oauthError("authorization-server-discovery", "Failed to process discovery response", {
          cause: processed.error,
        }),
      );
    }
    return processed;
  }

  return ok(null);
}

async function discoverResource(
  resource: string,
  customFetch: typeof fetch | undefined,
): Promise<
  AgentPwResult<{
    resource: string;
    authorizationServers: string[];
    resourceName?: string;
    scopes: string[];
  }>
> {
  const normalizedResource = normalizeResource(resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }

  const resourceUrl = assertUrl(normalizedResource.value, "resource");
  if (!resourceUrl.ok) {
    return resourceUrl;
  }

  const metadataResponse = await result(
    oauth.resourceDiscoveryRequest(
      resourceUrl.value,
      customFetch ? { [oauth.customFetch]: customFetch } : undefined,
    ),
  );
  if (!metadataResponse.ok) {
    return err(
      oauthError("resource-discovery", `Failed to discover resource '${resource}'`, {
        cause: metadataResponse.error,
      }),
    );
  }

  const resourceServer = await result(
    oauth.processResourceDiscoveryResponse(resourceUrl.value, metadataResponse.value),
  );
  if (!resourceServer.ok) {
    return err(
      oauthError("resource-discovery", `Failed to process resource metadata for '${resource}'`, {
        cause: resourceServer.error,
      }),
    );
  }

  return ok({
    resource: normalizedResource.value,
    authorizationServers: resourceServer.value.authorization_servers ?? [],
    resourceName: stringValue(resourceServer.value.resource_name),
    scopes: Array.isArray(resourceServer.value.scopes_supported)
      ? resourceServer.value.scopes_supported.filter(
          (entry): entry is string => typeof entry === "string",
        )
      : [],
  });
}

function cimdToClientMetadata(input: NonNullable<OAuthClientInput["metadata"]>) {
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
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "object" &&
          error !== null &&
          "message" in error &&
          typeof error.message === "string"
        ? error.message
        : "OAuth flow failed";
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
): AgentPwResult<OAuthResolvedConfig> {
  if (profile.auth.kind !== "oauth") {
    return err(inputError(`Credential Profile '${profile.path}' is not an OAuth profile`));
  }

  const clientId =
    profile.auth.clientId ?? clientInput?.clientId ?? clientInput?.metadata?.clientId;
  const clientSecret = profile.auth.clientSecret ?? clientInput?.clientSecret;
  const clientAuthentication = normalizeClientAuthentication(
    profile.auth.clientAuthentication ?? clientInput?.clientAuthentication,
    Boolean(clientSecret),
  );

  if (!clientId) {
    return err(
      inputError(`Credential Profile '${profile.path}' requires a clientId or default oauth client`),
    );
  }

  const normalizedResource = normalizeResource(resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }

  return ok({
    issuer: profile.auth.issuer,
    authorizationUrl: profile.auth.authorizationUrl,
    tokenUrl: profile.auth.tokenUrl,
    revocationUrl: profile.auth.revocationUrl,
    clientId,
    clientSecret,
    clientAuthentication,
    scopes: profile.auth.scopes,
    resource: normalizedResource.value,
  });
}

async function resolveOAuthConfigForResourceOption(
  option: ConnectOAuthOption,
  clientInput: OAuthClientInput | undefined,
  customFetch: typeof fetch | undefined,
): Promise<AgentPwResult<OAuthResolvedConfig>> {
  const client = clientInput;
  if (!client) {
    return err(inputError(`Resource '${option.resource}' requires oauth client configuration`));
  }

  const discovered = await discoverResource(option.resource, customFetch);
  if (!discovered.ok) {
    return discovered;
  }

  const issuer = option.authorizationServer ?? discovered.value.authorizationServers[0];
  if (!issuer) {
    return err(
      inputError(`Resource '${option.resource}' does not advertise an authorization server`),
    );
  }

  if (
    option.authorizationServer &&
    !discovered.value.authorizationServers.includes(option.authorizationServer)
  ) {
    return err(
      inputError(
        `Authorization server '${option.authorizationServer}' is not advertised for resource '${option.resource}'`,
      ),
    );
  }

  const issuerUrl = assertUrl(issuer, "authorization server");
  if (!issuerUrl.ok) {
    return issuerUrl;
  }

  const authorizationServer = await discoverAuthorizationServerMetadata(issuerUrl.value, customFetch);
  if (!authorizationServer.ok) {
    return authorizationServer;
  }
  if (!authorizationServer.value) {
    return err(inputError(`Authorization server '${issuer}' does not publish usable metadata`));
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
      return err(inputError("Dynamic client registration requires client metadata"));
    }
    if (!authorizationServer.value.registration_endpoint) {
      return err(
        inputError(
          `Authorization server '${authorizationServer.value.issuer}' does not support dynamic client registration`,
        ),
      );
    }

    const registrationResponse = await result(
      oauth.dynamicClientRegistrationRequest(
        authorizationServer.value,
        cimdToClientMetadata(client.metadata),
        {
          initialAccessToken: client.initialAccessToken,
          ...(customFetch ? { [oauth.customFetch]: customFetch } : {}),
        },
      ),
    );
    if (!registrationResponse.ok) {
      return err(
        oauthError("dynamic-client-registration", "Dynamic client registration failed", {
          cause: registrationResponse.error,
        }),
      );
    }

    const registered = await result(
      oauth.processDynamicClientRegistrationResponse(registrationResponse.value),
    );
    if (!registered.ok) {
      return err(
        oauthError(
          "dynamic-client-registration",
          "Failed to process dynamic client registration response",
          { cause: registered.error },
        ),
      );
    }
    clientId = stringValue(registered.value.client_id);
    clientSecret = stringValue(registered.value.client_secret);
    clientAuthentication = normalizeClientAuthentication(
      stringValue(registered.value.token_endpoint_auth_method),
      Boolean(clientSecret),
    );
  }

  if (!clientId) {
    return err(
      inputError(`Resource '${option.resource}' requires a clientId or dynamic client registration`),
    );
  }

  const normalizedResource = normalizeResource(option.resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }

  return ok({
    issuer: authorizationServer.value.issuer,
    authorizationUrl: authorizationServer.value.authorization_endpoint,
    tokenUrl: authorizationServer.value.token_endpoint,
    revocationUrl: authorizationServer.value.revocation_endpoint,
    clientId,
    clientSecret,
    clientAuthentication,
    scopes: option.scopes,
    resource: normalizedResource.value,
  } satisfies OAuthResolvedConfig);
}

export function createOAuthService(options: {
  flowStore?: FlowStore;
  clock: () => Date;
  customFetch?: typeof fetch;
  defaultClient?: OAuthClientInput;
  getProfile(path: string): Promise<AgentPwResult<CredentialProfileRecord | null>>;
  getCredential(path: string): Promise<AgentPwResult<CredentialRecord | null>>;
  putCredential(input: CredentialPutInput): Promise<AgentPwResult<CredentialRecord>>;
  deleteCredential(path: string): Promise<AgentPwResult<boolean>>;
}) {
  async function requireFlowStore(): Promise<AgentPwResult<FlowStore>> {
    if (!options.flowStore) {
      return err(inputError("OAuth flows require an explicit flowStore"));
    }
    return ok(options.flowStore);
  }

  async function resolveOAuthConfigForOption(
    option: ConnectOAuthOption,
    clientInput: OAuthClientInput | undefined,
  ): Promise<AgentPwResult<OAuthResolvedConfig>> {
    if (option.source === "profile") {
      if (!option.profilePath) {
        return err(inputError("Profile-backed OAuth option is missing profilePath"));
      }
      const profile = await options.getProfile(option.profilePath);
      if (!profile.ok) {
        return profile;
      }
      if (!profile.value) {
        return err(notFoundError("credential-profile", `Credential Profile '${option.profilePath}' does not exist`));
      }
      return parseProfileOAuthConfig(
        profile.value,
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
  ): Promise<AgentPwResult<CredentialRecord | null>> {
    const credential = await options.getCredential(path);
    if (!credential.ok) {
      return credential;
    }
    if (!credential.value) {
      return ok(null);
    }

    if (credential.value.auth.kind !== "oauth") {
      return ok(credential.value);
    }

    if (!shouldRefresh(credential.value.secret, options.clock, optionsForRefresh.force)) {
      return ok(credential.value);
    }

    const refreshToken = credential.value.secret.oauth?.refreshToken;
    if (!refreshToken) {
      return ok(credential.value);
    }

    const oauthConfig = oauthConfigFromStoredCredentials(
      credential.value.secret,
      resourceFromCredentialRecord(credential.value),
    );
    if (!oauthConfig) {
      return ok(credential.value);
    }

    const authorizationServer = await resolveAuthorizationServer(oauthConfig, options.customFetch);
    if (!authorizationServer.ok) {
      return authorizationServer;
    }
    const client = buildClient(oauthConfig);
    const clientAuthentication = buildClientAuthentication(oauthConfig);
    if (!clientAuthentication.ok) {
      return clientAuthentication;
    }
    const tokenResponse = await result(
      oauth.refreshTokenGrantRequest(
        authorizationServer.value,
        client,
        clientAuthentication.value,
        refreshToken,
        options.customFetch ? { [oauth.customFetch]: options.customFetch } : undefined,
      ),
    );
    if (!tokenResponse.ok) {
      return err(
        oauthError("refresh", `Failed to refresh credential for '${path}'`, {
          cause: tokenResponse.error,
          path,
        }),
      );
    }
    const processed = await result(
      oauth.processRefreshTokenResponse(
        authorizationServer.value,
        client,
        tokenResponse.value,
      ),
    );
    if (!processed.ok) {
      return err(
        oauthError("refresh", `Failed to process refresh response for '${path}'`, {
          cause: processed.error,
          path,
        }),
      );
    }
    return options.putCredential({
      path: credential.value.path,
      auth: credential.value.auth,
      secret: oauthSecretFromTokenResponse(processed.value, oauthConfig, credential.value.secret),
    });
  }

  return {
    async getFlow(id: string) {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }
      return ok(await flowStore.value.get(id));
    },

    async discoverResource(input: { resource: string; response?: Response }) {
      return discoverResource(input.resource, options.customFetch);
    },

    async startAuthorization(
      input: ConnectStartInput,
    ): Promise<AgentPwResult<ConnectAuthorizationSession>> {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return path;
      }
      const redirectUri = assertUrl(input.redirectUri, "redirect uri");
      if (!redirectUri.ok) {
        return redirectUri;
      }
      const context = jsonObject(input.context, "OAuth context");
      if (!context.ok) {
        return context;
      }
      const reason = normalizeStartReason(input.reason);
      const oauthConfig = await resolveOAuthConfigForOption(input.option, input.client);
      if (!oauthConfig.ok) {
        return oauthConfig;
      }
      const authorizationServer = await resolveAuthorizationServer(
        oauthConfig.value,
        options.customFetch,
      );
      if (!authorizationServer.ok) {
        return authorizationServer;
      }
      if (!authorizationServer.value.authorization_endpoint) {
        return err(inputError(
          `OAuth option for '${input.option.resource}' is missing an authorization endpoint`,
        ));
      }

      const flowId = validateFlowId(undefined) ?? randomId() + randomId();
      const codeVerifier = oauth.generateRandomCodeVerifier();
      const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
      const authorizationUrl = new URL(authorizationServer.value.authorization_endpoint);

      authorizationUrl.searchParams.set("client_id", oauthConfig.value.clientId);
      authorizationUrl.searchParams.set("redirect_uri", redirectUri.value.toString());
      authorizationUrl.searchParams.set("response_type", "code");
      authorizationUrl.searchParams.set("state", flowId);
      authorizationUrl.searchParams.set("code_challenge", codeChallenge);
      authorizationUrl.searchParams.set("code_challenge_method", "S256");
      authorizationUrl.searchParams.set("resource", oauthConfig.value.resource);

      const scopes = toScopeString(input.scopes) ?? toScopeString(oauthConfig.value.scopes);
      if (scopes) {
        authorizationUrl.searchParams.set("scope", scopes);
      }

      for (const [key, value] of Object.entries(input.additionalParameters ?? {})) {
        authorizationUrl.searchParams.set(key, value);
      }

      const flow: PendingFlow = {
        id: flowId,
        path: path.value,
        resource: oauthConfig.value.resource,
        option: input.option,
        redirectUri: redirectUri.value.toString(),
        codeVerifier,
        expiresAt: input.expiresAt ?? defaultExpiry(options.clock),
        oauthConfig: oauthConfig.value,
        context: context.value,
        reason,
      };
      await flowStore.value.create(flow);

      return ok({
        flowId,
        authorizationUrl: authorizationUrl.toString(),
        expiresAt: flow.expiresAt,
        path: flow.path,
        resource: flow.resource,
        option: flow.option,
        context: flow.context,
        reason: flow.reason,
      });
    },

    async completeAuthorization(
      input: ConnectCompleteInput,
    ): Promise<AgentPwResult<ConnectCompleteResult>> {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }

      const callbackUrl = assertUrl(input.callbackUri, "callback uri");
      if (!callbackUrl.ok) {
        return callbackUrl;
      }

      const flowId = callbackUrl.value.searchParams.get("state");
      if (!flowId) {
        return err(inputError("OAuth callback is missing state"));
      }

      const flow = await flowStore.value.get(flowId);
      if (!flow) {
        return err(notFoundError("oauth-flow", `Unknown OAuth flow '${flowId}'`));
      }
      if (flow.expiresAt.getTime() <= options.clock().getTime()) {
        await flowStore.value.delete(flow.id);
        return err(expiredError("oauth-flow", `OAuth flow '${flow.id}' has expired`));
      }

      const authorizationServer = await resolveAuthorizationServer(flow.oauthConfig, options.customFetch);
      if (!authorizationServer.ok) {
        return authorizationServer;
      }

      const client = buildClient(flow.oauthConfig);
      const clientAuthentication = buildClientAuthentication(flow.oauthConfig);
      if (!clientAuthentication.ok) {
        return clientAuthentication;
      }

      const validated = result(() =>
        oauth.validateAuthResponse(
          authorizationServer.value,
          client,
          callbackUrl.value,
          flow.id,
        ),
      );
      if (!validated.ok) {
        return err(
          oauthError("authorization-callback", "Failed to validate OAuth callback", {
            cause: validated.error,
            path: flow.path,
          }),
        );
      }

      const tokenResponse = await result(
        oauth.authorizationCodeGrantRequest(
          authorizationServer.value,
          client,
          clientAuthentication.value,
          validated.value,
          flow.redirectUri,
          flow.codeVerifier,
          options.customFetch ? { [oauth.customFetch]: options.customFetch } : undefined,
        ),
      );
      if (!tokenResponse.ok) {
        return err(
          oauthError("authorization-code", "Failed to exchange authorization code", {
            cause: tokenResponse.error,
            path: flow.path,
          }),
        );
      }

      const processed = await result(
        oauth.processAuthorizationCodeResponse(
          authorizationServer.value,
          client,
          tokenResponse.value,
        ),
      );
      if (!processed.ok) {
        return err(
          oauthError("authorization-code", "Failed to process authorization code response", {
            cause: processed.error,
            path: flow.path,
          }),
        );
      }

      const existing =
        input.merge === "preserve-non-auth-headers" ? await options.getCredential(flow.path) : ok(null);
      if (!existing.ok) {
        return existing;
      }

      const secret = oauthSecretFromTokenResponse(processed.value, flow.oauthConfig);
      secret.headers = mergeHeaders(existing.value?.secret.headers, secret.headers, input.merge);

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
      if (!credential.ok) {
        return credential;
      }

      await flowStore.value.complete(flow.id, {
        context: flow.context,
        reason: flow.reason,
      });

      return ok({
        path: flow.path,
        credential: credential.value,
        context: flow.context,
        reason: flow.reason,
      });
    },

    async refreshCredential(path: string, force = false) {
      const normalizedPath = assertPath(path, "path");
      if (!normalizedPath.ok) {
        return normalizedPath;
      }
      return refreshCredential(normalizedPath.value, { force });
    },

    async disconnect(input: ConnectDisconnectInput) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return path;
      }

      const credential = await options.getCredential(path.value);
      if (!credential.ok) {
        return credential;
      }
      if (!credential.value) {
        return ok(false);
      }

      if (credential.value.auth.kind === "oauth") {
        const oauthConfig = oauthConfigFromStoredCredentials(
          credential.value.secret,
          resourceFromCredentialRecord(credential.value),
        );
        const revokeMode = input.revoke ?? "refresh_token";
        if (oauthConfig) {
          const authorizationServer = await resolveAuthorizationServer(
            oauthConfig,
            options.customFetch,
          );
          if (!authorizationServer.ok) {
            return authorizationServer;
          }
          if (authorizationServer.value.revocation_endpoint) {
            const client = buildClient(oauthConfig);
            const clientAuthentication = buildClientAuthentication(oauthConfig);
            if (!clientAuthentication.ok) {
              return clientAuthentication;
            }

            if (
              (revokeMode === "refresh_token" || revokeMode === "both") &&
              credential.value.secret.oauth?.refreshToken
            ) {
              const response = await result(
                oauth.revocationRequest(
                  authorizationServer.value,
                  client,
                  clientAuthentication.value,
                  credential.value.secret.oauth.refreshToken,
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
                ),
              );
              if (!response.ok) {
                return err(
                  oauthError("revoke", "Failed to revoke refresh token", {
                    cause: response.error,
                    path: path.value,
                  }),
                );
              }
              const processed = await result(oauth.processRevocationResponse(response.value));
              if (!processed.ok) {
                return err(
                  oauthError("revoke", "Failed to process refresh token revocation", {
                    cause: processed.error,
                    path: path.value,
                  }),
                );
              }
            }

            if (
              (revokeMode === "access_token" || revokeMode === "both") &&
              credential.value.secret.oauth?.accessToken
            ) {
              const response = await result(
                oauth.revocationRequest(
                  authorizationServer.value,
                  client,
                  clientAuthentication.value,
                  credential.value.secret.oauth.accessToken,
                  options.customFetch
                    ? {
                        [oauth.customFetch]: options.customFetch,
                        additionalParameters: { token_type_hint: "access_token" },
                      }
                    : {
                        additionalParameters: { token_type_hint: "access_token" },
                      },
                ),
              );
              if (!response.ok) {
                return err(
                  oauthError("revoke", "Failed to revoke access token", {
                    cause: response.error,
                    path: path.value,
                  }),
                );
              }
              const processed = await result(oauth.processRevocationResponse(response.value));
              if (!processed.ok) {
                return err(
                  oauthError("revoke", "Failed to process access token revocation", {
                    cause: processed.error,
                    path: path.value,
                  }),
                );
              }
            }
          }
        }
      }

      return options.deleteCredential(path.value);
    },

    createWebHandlers(
      optionsForHandlers: {
        callbackPath?: string;
        success?(result: ConnectCompleteResult, request: Request): Response | Promise<Response>;
        error?(error: AgentPwError, request: Request): Response | Promise<Response>;
      } = {},
    ): ConnectWebHandlers {
      const callbackPath = optionsForHandlers.callbackPath ?? "/oauth/callback";

      return {
        start: async (request, input) => {
          try {
            const path = assertPath(input.path, "path");
            if (!path.ok) {
              return optionsForHandlers.error
                ? optionsForHandlers.error(path.error, request)
                : defaultErrorResponse(path.error);
            }

            const session = await this.startAuthorization({
              ...input,
              path: path.value,
              redirectUri: input.redirectUri ?? resolveRedirectUri(request, callbackPath),
            });
            if (!session.ok) {
              return optionsForHandlers.error
                ? optionsForHandlers.error(session.error, request)
                : defaultErrorResponse(session.error);
            }
            return Response.redirect(session.value.authorizationUrl, 302);
          } catch (error) {
            const normalized = internalError("OAuth start failed", {
              cause: error,
              source: "oauth.createWebHandlers.start",
            });
            return optionsForHandlers.error
              ? optionsForHandlers.error(normalized, request)
              : defaultErrorResponse(normalized);
          }
        },

        callback: async (request) => {
          try {
            const completed = await this.completeAuthorization({
              callbackUri: request.url,
            });
            if (!completed.ok) {
              return optionsForHandlers.error
                ? optionsForHandlers.error(completed.error, request)
                : defaultErrorResponse(completed.error);
            }
            if (optionsForHandlers.success) {
              return optionsForHandlers.success(completed.value, request);
            }
            return defaultSuccessResponse();
          } catch (error) {
            const normalized = internalError("OAuth flow failed", {
              cause: error,
              source: "oauth.createWebHandlers.callback",
            });
            return optionsForHandlers.error
              ? optionsForHandlers.error(normalized, request)
              : defaultErrorResponse(normalized);
          }
        },
      };
    },

    createClientMetadataDocument(input: CimdDocumentInput): AgentPwResult<CimdDocument> {
      const clientId = assertUrl(input.clientId, "client id");
      if (!clientId.ok) {
        return clientId;
      }
      if (input.redirectUris.length === 0) {
        return err(inputError("CIMD requires at least one redirect URI"));
      }

      const redirectUris = [];
      for (const uri of input.redirectUris) {
        const redirectUri = assertUrl(uri, "redirect uri");
        if (!redirectUri.ok) {
          return redirectUri;
        }
        redirectUris.push(redirectUri.value.toString());
      }

      const jwksUri = input.jwksUri ? assertUrl(input.jwksUri, "jwks uri") : ok<URL | undefined>(undefined);
      if (!jwksUri.ok) {
        return jwksUri;
      }

      return ok({
        client_id: clientId.value.toString(),
        redirect_uris: redirectUris,
        response_types: ["code"],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? "none",
        client_name: input.clientName,
        scope: toScopeString(input.scope),
        jwks_uri: jwksUri.value?.toString(),
        jwks: input.jwks,
        token_endpoint_auth_signing_alg: input.tokenEndpointAuthSigningAlg,
      });
    },

    createClientMetadataResponse(input: CimdDocumentInput): AgentPwResult<Response> {
      const document = this.createClientMetadataDocument(input);
      if (!document.ok) {
        return document;
      }
      return ok(
        new Response(JSON.stringify(document.value, null, 2), {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "public, max-age=300",
          },
        }),
      );
    },
  };
}
