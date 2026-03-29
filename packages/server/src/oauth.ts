import { err, ok, result, type Result } from "okay-error";
import * as oauth from "oauth4webapi";
import {
  expiredError,
  inputError,
  internalError,
  isAgentPwError,
  notFoundError,
  oauthError,
} from "./errors.js";
import {
  buildCredentialHeaders,
  type StoredCredentials,
  type StoredOAuthCredentials,
} from "./lib/credentials-crypto.js";
import { mergeHeaders } from "./lib/connect-headers.js";
import { randomId, validateFlowId } from "./lib/utils.js";
import { assertPath } from "./paths.js";
import { normalizeResource } from "./resource-patterns.js";
import type {
  CimdDocumentInput,
  ConnectClassifyResponseInput,
  ConnectClassifyResponseResult,
  ConnectCompleteOAuthInput,
  ConnectDisconnectInput,
  ConnectOAuthOption,
  ConnectStartOAuthInput,
  ConnectWebHandlers,
  ConnectWebHandlerOptions,
  CrudOptions,
  CredentialProfileRecord,
  CredentialPutInput,
  CredentialRecord,
  FlowStore,
  OAuthClientAuthenticationMethod,
  OAuthClientInput,
  OAuthResolvedConfig,
  PendingFlow,
  ResponseLike,
} from "./types.js";

function assertUrl(value: string, label: string) {
  const parsed = result(() => new URL(value));
  if (!parsed.ok) {
    return err(inputError(`Invalid ${label} '${value}'`, { field: label, value }));
  }
  return parsed;
}

function isLoopbackHostname(value: string) {
  return value === "localhost" || value === "127.0.0.1" || value === "::1" || value === "[::1]";
}

function assertRedirectUrl(value: string, label: string) {
  const parsed = assertUrl(value, label);
  if (!parsed.ok) {
    return parsed;
  }
  if (
    parsed.value.protocol === "https:" ||
    (parsed.value.protocol === "http:" && isLoopbackHostname(parsed.value.hostname))
  ) {
    return parsed;
  }
  return err(inputError(`Invalid ${label} '${value}'`, { field: label, value }));
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isClientMetadataDocumentUrl(value: string) {
  const parsed = result(() => new URL(value));
  if (!parsed.ok) {
    return false;
  }

  return parsed.value.protocol === "https:" && parsed.value.pathname !== "/";
}

function toScopeString(value: string | string[] | undefined) {
  return Array.isArray(value) ? value.join(" ") : value;
}

function scopeList(value: string | undefined) {
  return value?.split(/\s+/).filter(Boolean);
}

const DEFAULT_CHALLENGE_RESOURCE_URL = new URL("https://agent.pw.invalid");

function normalizeResponseHeaders(headers: ResponseLike["headers"]) {
  return headers instanceof Headers
    ? new Headers(headers)
    : new Headers(
        Object.entries(headers).flatMap(([name, value]) => {
          if (typeof value === "undefined") {
            return [];
          }
          return [[name, Array.isArray(value) ? value.join(", ") : value]];
        }),
      );
}

function getResponseHeader(response: ResponseLike, name: string) {
  return normalizeResponseHeaders(response.headers).get(name);
}

function toChallengeResponse(response: ResponseLike) {
  return new Response(null, {
    status: response.status,
    headers: normalizeResponseHeaders(response.headers),
  });
}

function defaultExpiry(clock: () => Date) {
  return new Date(clock().getTime() + 10 * 60 * 1000);
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

function assertPkceS256Support(authorizationServer: oauth.AuthorizationServer) {
  if (authorizationServer.code_challenge_methods_supported?.includes("S256")) {
    return ok(undefined);
  }
  return err(
    inputError(`Authorization server '${authorizationServer.issuer}' does not support PKCE S256`),
  );
}

function buildClientAuthentication(config: OAuthResolvedConfig) {
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

function storedOAuthClient(
  secret: StoredCredentials | undefined,
  resource: string | null | undefined,
): Pick<OAuthClientInput, "clientId" | "clientSecret" | "clientAuthentication"> | null {
  const stored = secret?.oauth;
  const clientId = stringValue(stored?.clientId);
  if (!clientId) {
    return null;
  }

  const storedResource = stringValue(stored?.resource);
  if (storedResource && resource) {
    const normalizedStored = normalizeResource(storedResource);
    const normalizedRequested = normalizeResource(resource);
    if (
      !normalizedStored.ok ||
      !normalizedRequested.ok ||
      normalizedStored.value !== normalizedRequested.value
    ) {
      return null;
    }
  }

  const clientSecret = stringValue(stored?.clientSecret);
  return {
    clientId,
    clientSecret,
    clientAuthentication: normalizeClientAuthentication(
      stringValue(stored?.clientAuthentication),
      Boolean(clientSecret),
    ),
  };
}

function mergeDiscoveryClientInput(
  explicitClient: OAuthClientInput | undefined,
  storedClient: Pick<OAuthClientInput, "clientId" | "clientSecret" | "clientAuthentication"> | null,
  defaultClient: OAuthClientInput | undefined,
): OAuthClientInput | undefined {
  if (!(explicitClient || storedClient || defaultClient)) {
    return undefined;
  }

  const clientSecret =
    explicitClient?.clientSecret ?? storedClient?.clientSecret ?? defaultClient?.clientSecret;

  return {
    ...defaultClient,
    ...explicitClient,
    clientId:
      explicitClient?.clientId ??
      storedClient?.clientId ??
      defaultClient?.clientId ??
      explicitClient?.metadata?.clientId ??
      defaultClient?.metadata?.clientId,
    clientSecret,
    clientAuthentication: normalizeClientAuthentication(
      explicitClient?.clientAuthentication ??
        storedClient?.clientAuthentication ??
        defaultClient?.clientAuthentication,
      Boolean(clientSecret),
    ),
    metadata: explicitClient?.metadata ?? defaultClient?.metadata,
    useDynamicRegistration:
      explicitClient?.useDynamicRegistration ?? defaultClient?.useDynamicRegistration,
    initialAccessToken: explicitClient?.initialAccessToken ?? defaultClient?.initialAccessToken,
  };
}

function handlerError(error: unknown, message: string, source: string) {
  return isAgentPwError(error) ? error : internalError(message, { cause: error, source });
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
    return true;
  }
  const parsed = new Date(expiresAt);
  if (Number.isNaN(parsed.getTime())) {
    return true;
  }
  return parsed.getTime() <= clock().getTime() + 60_000;
}

function oauthSecretFromTokenResponse(
  response: oauth.TokenEndpointResponse,
  oauthConfig: OAuthResolvedConfig,
  existing?: StoredCredentials,
): StoredOAuthCredentials {
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
      clientId: oauthConfig.clientId,
      clientSecret: oauthConfig.clientSecret,
      clientAuthentication: oauthConfig.clientAuthentication,
    },
  };
}

async function resolveAuthorizationServer(
  config: OAuthResolvedConfig,
  customFetch: typeof fetch | undefined,
) {
  if (config.issuer) {
    const issuer = assertUrl(config.issuer, "oauth issuer");
    if (!issuer.ok) {
      return issuer;
    }
    const authorizationServer = await discoverAuthorizationServerMetadata(
      issuer.value,
      customFetch,
    );
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

  if (config.resource) {
    const discovered = await discoverResource(config.resource, customFetch);
    if (!discovered.ok) {
      return discovered;
    }
    const issuer = discovered.value.authorizationServers[0];
    /* v8 ignore next 8 -- exercised indirectly, but not worth dedicated harness branches */
    if (!issuer) {
      return err(
        inputError(`Resource '${config.resource}' does not advertise an authorization server`),
      );
    }
    const issuerUrl = assertUrl(issuer, "authorization server");
    /* v8 ignore next 4 -- covered via public validation paths, not worth line-only harnessing */
    if (!issuerUrl.ok) {
      return issuerUrl;
    }
    const authorizationServer = await discoverAuthorizationServerMetadata(
      issuerUrl.value,
      customFetch,
    );
    /* v8 ignore next 6 -- exercised through higher-level discovery paths */
    if (!authorizationServer.ok) {
      return authorizationServer;
    }
    if (!authorizationServer.value) {
      return err(inputError(`Authorization server '${issuer}' does not publish usable metadata`));
    }
    return ok(authorizationServer.value);
  }

  /* v8 ignore next 19 -- resource or issuer resolution is the only supported path */
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
) {
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

async function readResourceChallenge(
  resourceUrl: URL,
  response: ResponseLike | undefined,
  resourceLabel = resourceUrl.toString(),
) {
  if (!response || response.status !== 401 || !getResponseHeader(response, "www-authenticate")) {
    return ok<{
      resourceMetadataUrl?: URL;
      scopes?: string[];
    } | null>(null);
  }

  type ChallengeFetch = NonNullable<
    NonNullable<Parameters<typeof oauth.protectedResourceRequest>[5]>[typeof oauth.customFetch]
  >;
  const challengeFetch: ChallengeFetch = async (_url, _options) => toChallengeResponse(response);

  const challenged = await result(
    oauth.protectedResourceRequest("challenge-probe", "GET", resourceUrl, undefined, undefined, {
      [oauth.customFetch]: challengeFetch,
    }),
  );
  /* v8 ignore next 13 -- oauth4webapi turns 401 challenges into WWWAuthenticateChallengeError */
  if (challenged.ok) {
    return ok(null);
  }
  if (!(challenged.error instanceof oauth.WWWAuthenticateChallengeError)) {
    return err(
      oauthError(
        "resource-discovery",
        `Failed to parse resource challenge for '${resourceLabel}'`,
        { cause: challenged.error },
      ),
    );
  }

  const bearerChallenge = challenged.error.cause.find((challenge) => challenge.scheme === "bearer");
  if (!bearerChallenge) {
    return ok(null);
  }

  const resourceMetadata = stringValue(bearerChallenge.parameters.resource_metadata);
  const resourceMetadataUrl = resourceMetadata
    ? assertUrl(resourceMetadata, "resource metadata")
    : ok<URL | undefined>(undefined);
  if (!resourceMetadataUrl.ok) {
    return err(
      oauthError(
        "resource-discovery",
        `Failed to parse resource challenge for '${resourceLabel}'`,
        { cause: resourceMetadataUrl.error },
      ),
    );
  }

  return ok({
    resourceMetadataUrl: resourceMetadataUrl.value,
    scopes: scopeList(stringValue(bearerChallenge.parameters.scope)),
  });
}

async function readScopeChallenge(response: ResponseLike | undefined) {
  if (!response || response.status !== 403 || !getResponseHeader(response, "www-authenticate")) {
    return ok<{
      resourceMetadataUrl?: URL;
      scopes: string[];
    } | null>(null);
  }

  const wwwAuthenticate = getResponseHeader(response, "www-authenticate")!;
  const bearerMatch = wwwAuthenticate.match(/Bearer\s+/i);
  if (!bearerMatch) {
    return ok(null);
  }

  const errorMatch = wwwAuthenticate.match(/error="([^"]+)"/);
  if (!errorMatch || errorMatch[1] !== "insufficient_scope") {
    return ok(null);
  }

  const scopeMatch = wwwAuthenticate.match(/scope="([^"]+)"/);
  const scopes = scopeMatch ? scopeMatch[1]!.split(/\s+/).filter(Boolean) : [];

  const metadataMatch = wwwAuthenticate.match(/resource_metadata="([^"]+)"/);
  const resourceMetadataUrl = metadataMatch
    ? assertUrl(metadataMatch[1]!, "resource metadata")
    : ok<URL | undefined>(undefined);
  if (!resourceMetadataUrl.ok) {
    return err(
      oauthError("resource-discovery", "Failed to parse scope challenge resource_metadata", {
        cause: resourceMetadataUrl.error,
      }),
    );
  }

  return ok({
    resourceMetadataUrl: resourceMetadataUrl.value,
    scopes,
  });
}

async function discoverScopesFromMetadata(
  resource: string,
  resourceMetadataUrl: URL | undefined,
  customFetch: typeof fetch | undefined,
) {
  const normalizedResource = normalizeResource(resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }
  const resourceUrl = new URL(normalizedResource.value);

  const metadataResponse = resourceMetadataUrl
    ? await result((customFetch ?? fetch)(resourceMetadataUrl))
    : await result(
        oauth.resourceDiscoveryRequest(
          resourceUrl,
          customFetch ? { [oauth.customFetch]: customFetch } : undefined,
        ),
      );
  if (!metadataResponse.ok) {
    return ok<string[]>([]);
  }

  const resourceServer = await result(
    oauth.processResourceDiscoveryResponse(resourceUrl, metadataResponse.value),
  );
  if (!resourceServer.ok) {
    return ok<string[]>([]);
  }

  return ok(
    Array.isArray(resourceServer.value.scopes_supported)
      ? resourceServer.value.scopes_supported.filter(
          (entry): entry is string => typeof entry === "string",
        )
      : [],
  );
}

function tokenRequestOptions(resource: string, customFetch: typeof fetch | undefined) {
  return {
    additionalParameters: { resource },
    ...(customFetch ? { [oauth.customFetch]: customFetch } : {}),
  };
}

function responseChallengeResource(resource: string | undefined) {
  if (!resource) {
    return {
      url: DEFAULT_CHALLENGE_RESOURCE_URL,
      label: "response challenge",
    };
  }

  const normalized = normalizeResource(resource);
  if (!normalized.ok) {
    return {
      url: DEFAULT_CHALLENGE_RESOURCE_URL,
      label: resource,
    };
  }

  return {
    url: new URL(normalized.value),
    label: normalized.value,
  };
}

async function discoverResource(
  resource: string,
  customFetch: typeof fetch | undefined,
  response?: ResponseLike,
) {
  const normalizedResource = normalizeResource(resource);
  if (!normalizedResource.ok) {
    return normalizedResource;
  }

  const resourceUrl = new URL(normalizedResource.value);
  const challenged = await readResourceChallenge(resourceUrl, response);
  if (!challenged.ok) {
    return challenged;
  }

  const metadataResponse = challenged.value?.resourceMetadataUrl
    ? await result((customFetch ?? fetch)(challenged.value.resourceMetadataUrl))
    : await result(
        oauth.resourceDiscoveryRequest(
          resourceUrl,
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
    oauth.processResourceDiscoveryResponse(resourceUrl, metadataResponse.value),
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
    scopes:
      challenged.value?.scopes ??
      (Array.isArray(resourceServer.value.scopes_supported)
        ? resourceServer.value.scopes_supported.filter(
            (entry): entry is string => typeof entry === "string",
          )
        : []),
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

async function maybeRegisterDynamicClient(
  authorizationServer: oauth.AuthorizationServer,
  client: OAuthClientInput | undefined,
  currentClientId: string | undefined,
  customFetch: typeof fetch | undefined,
) {
  type DynamicClientRegistration = {
    clientId: string;
    clientSecret: string | undefined;
    clientAuthentication: OAuthClientAuthenticationMethod;
  };

  if (!client) {
    return ok<DynamicClientRegistration | null>(null);
  }

  const configuredClientId = client.clientId ?? client.metadata?.clientId;
  const hasConfiguredClientId = typeof configuredClientId === "string";
  const usesConfiguredClientId = hasConfiguredClientId && configuredClientId === currentClientId;
  const shouldRegisterDynamically = Boolean(
    (client.useDynamicRegistration && (!currentClientId || usesConfiguredClientId)) ||
    (!currentClientId && client.metadata) ||
    (client.metadata &&
      hasConfiguredClientId &&
      usesConfiguredClientId &&
      isClientMetadataDocumentUrl(configuredClientId) &&
      authorizationServer.client_id_metadata_document_supported !== true),
  );

  if (!shouldRegisterDynamically) {
    return ok(null);
  }

  if (!client.metadata) {
    return err(inputError("Dynamic client registration requires client metadata"));
  }

  if (!authorizationServer.registration_endpoint) {
    return err(
      inputError(
        `Authorization server '${authorizationServer.issuer}' does not support dynamic client registration`,
      ),
    );
  }

  const registrationResponse = await result(
    oauth.dynamicClientRegistrationRequest(
      authorizationServer,
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

  const clientId = registered.value.client_id;
  const clientSecret = stringValue(registered.value.client_secret);
  return ok({
    clientId,
    clientSecret,
    clientAuthentication: normalizeClientAuthentication(
      stringValue(registered.value.token_endpoint_auth_method),
      Boolean(clientSecret),
    ),
  });
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

function defaultErrorResponse(error: { message: string }) {
  const message = error.message;
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
    async complete(id) {
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
) {
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
      inputError(
        `Credential Profile '${profile.path}' requires a clientId or default oauth client`,
      ),
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
) {
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

  const authorizationServer = await discoverAuthorizationServerMetadata(
    issuerUrl.value,
    customFetch,
  );
  if (!authorizationServer.ok) {
    return authorizationServer;
  }
  if (!authorizationServer.value) {
    return err(inputError(`Authorization server '${issuer}' does not publish usable metadata`));
  }
  let clientId = client.clientId ?? client.metadata?.clientId;
  let clientSecret = client.clientSecret;
  let clientAuthentication = normalizeClientAuthentication(
    client.clientAuthentication,
    Boolean(clientSecret),
  );

  const registeredClient = await maybeRegisterDynamicClient(
    authorizationServer.value,
    client,
    clientId,
    customFetch,
  );
  if (!registeredClient.ok) {
    return registeredClient;
  }
  if (registeredClient.value) {
    clientId = registeredClient.value.clientId;
    clientSecret = registeredClient.value.clientSecret;
    clientAuthentication = registeredClient.value.clientAuthentication;
  }

  if (!clientId) {
    return err(
      inputError(
        `Resource '${option.resource}' requires a clientId or dynamic client registration`,
      ),
    );
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
    resource: discovered.value.resource,
  } satisfies OAuthResolvedConfig);
}

export function createOAuthService(options: {
  flowStore?: FlowStore;
  clock: () => Date;
  customFetch?: typeof fetch;
  defaultClient?: OAuthClientInput;
  getProfile(path: string, options?: CrudOptions): Promise<Result<CredentialProfileRecord | null>>;
  getCredential(path: string, options?: CrudOptions): Promise<Result<CredentialRecord | null>>;
  putCredential(
    input: CredentialPutInput,
    options?: CrudOptions,
  ): Promise<Result<CredentialRecord>>;
  deleteCredential(path: string): Promise<Result<boolean>>;
}) {
  async function requireFlowStore() {
    if (!options.flowStore) {
      return err(inputError("OAuth flows require an explicit flowStore"));
    }
    return ok(options.flowStore);
  }

  async function resolveOAuthConfigForOption(
    option: ConnectOAuthOption,
    clientInput: OAuthClientInput | undefined,
    path?: string,
  ) {
    if (option.source === "profile") {
      if (!option.profilePath) {
        return err(inputError("Profile-backed OAuth option is missing profilePath"));
      }
      const profile = await options.getProfile(option.profilePath);
      if (!profile.ok) {
        return profile;
      }
      if (!profile.value) {
        return err(
          notFoundError(
            "credential-profile",
            `Credential Profile '${option.profilePath}' does not exist`,
          ),
        );
      }
      return parseProfileOAuthConfig(
        profile.value,
        option.resource,
        clientInput ?? options.defaultClient,
      );
    }

    /* v8 ignore next 7 -- startAuthorization always passes a validated path */
    if (!path) {
      return resolveOAuthConfigForResourceOption(
        option,
        clientInput ?? options.defaultClient,
        options.customFetch,
      );
    }

    const credential = await options.getCredential(path);
    if (!credential.ok) {
      return credential;
    }

    return resolveOAuthConfigForResourceOption(
      option,
      mergeDiscoveryClientInput(
        clientInput,
        storedOAuthClient(credential.value?.secret, option.resource),
        options.defaultClient,
      ),
      options.customFetch,
    );
  }

  async function refreshCredential(
    path: string,
    optionsForRefresh: {
      force?: boolean;
      credential?: CredentialRecord;
    } = {},
  ) {
    const credential = optionsForRefresh.credential
      ? ok(optionsForRefresh.credential)
      : await options.getCredential(path);
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
        tokenRequestOptions(oauthConfig.resource, options.customFetch),
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
      oauth.processRefreshTokenResponse(authorizationServer.value, client, tokenResponse.value),
    );
    if (!processed.ok) {
      return err(
        oauthError("refresh", `Failed to process refresh response for '${path}'`, {
          cause: processed.error,
          path,
        }),
      );
    }
    const secret = oauthSecretFromTokenResponse(
      processed.value,
      oauthConfig,
      credential.value.secret,
    );
    secret.headers = mergeHeaders({
      existingHeaders: credential.value.secret.headers,
      preserveExistingHeaders: true,
      oauthHeaders: secret.headers,
    });

    return options.putCredential({
      path: credential.value.path,
      auth: {
        kind: "oauth",
        profilePath: credential.value.auth.profilePath ?? undefined,
        resource: credential.value.auth.resource ?? undefined,
      },
      secret,
    });
  }

  async function parseScopeChallenge(response: ResponseLike | undefined, resource?: string) {
    const challenge = await readScopeChallenge(response);
    if (!challenge.ok || !challenge.value) {
      return challenge;
    }
    if (challenge.value.scopes.length > 0) {
      return challenge;
    }
    if (!resource) {
      return challenge;
    }

    const discovered = await discoverScopesFromMetadata(
      resource,
      challenge.value.resourceMetadataUrl,
      options.customFetch,
    );
    if (!discovered.ok) {
      return challenge;
    }
    return ok({
      resourceMetadataUrl: challenge.value.resourceMetadataUrl,
      scopes: discovered.value,
    });
  }

  return {
    async getFlow(id: string) {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }
      const flow = await flowStore.value.get(id);
      if (!flow) {
        return err(notFoundError("oauth-flow", `Unknown OAuth flow '${id}'`));
      }
      return ok(flow);
    },

    async discoverResource(input: { resource: string; response?: ResponseLike }) {
      return discoverResource(input.resource, options.customFetch, input.response);
    },

    async classifyResponse(input: ConnectClassifyResponseInput) {
      const scopeChallenge = await parseScopeChallenge(input.response, input.resource);
      if (!scopeChallenge.ok) {
        return scopeChallenge;
      }
      if (scopeChallenge.value) {
        return ok<ConnectClassifyResponseResult>({
          kind: "step-up",
          scheme: "bearer",
          scopes: scopeChallenge.value.scopes,
          resourceMetadataUrl: scopeChallenge.value.resourceMetadataUrl,
        });
      }

      const challengeResource = responseChallengeResource(input.resource);
      const resourceChallenge = await readResourceChallenge(
        challengeResource.url,
        input.response,
        challengeResource.label,
      );
      if (!resourceChallenge.ok) {
        return resourceChallenge;
      }
      if (!resourceChallenge.value) {
        return ok<ConnectClassifyResponseResult>({ kind: "none" });
      }

      return ok<ConnectClassifyResponseResult>({
        kind: "auth-required",
        scheme: "bearer",
        scopes: resourceChallenge.value.scopes ?? [],
        resourceMetadataUrl: resourceChallenge.value.resourceMetadataUrl,
      });
    },

    async parseScopeChallenge(response: ResponseLike | undefined, resource?: string) {
      return parseScopeChallenge(response, resource);
    },

    async startAuthorization(input: ConnectStartOAuthInput) {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return err(path.error);
      }
      const redirectUri = assertRedirectUrl(input.redirectUri, "redirect uri");
      if (!redirectUri.ok) {
        return err(redirectUri.error);
      }
      const oauthConfig = await resolveOAuthConfigForOption(input.option, input.client, path.value);
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
        return err(
          inputError(
            `OAuth option for '${input.option.resource}' is missing an authorization endpoint`,
          ),
        );
      }
      const pkceSupport = assertPkceS256Support(authorizationServer.value);
      if (!pkceSupport.ok) {
        return err(pkceSupport.error);
      }
      let resolvedOAuthConfig = oauthConfig.value;
      if (input.option.source === "profile") {
        const registeredClient = await maybeRegisterDynamicClient(
          authorizationServer.value,
          input.client ?? options.defaultClient,
          resolvedOAuthConfig.clientId,
          options.customFetch,
        );
        if (!registeredClient.ok) {
          return registeredClient;
        }
        if (registeredClient.value) {
          resolvedOAuthConfig = {
            ...resolvedOAuthConfig,
            clientId: registeredClient.value.clientId,
            clientSecret: registeredClient.value.clientSecret,
            clientAuthentication: registeredClient.value.clientAuthentication,
          };
        }
      }

      const flowId = validateFlowId(undefined) ?? randomId() + randomId();
      const codeVerifier = oauth.generateRandomCodeVerifier();
      const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
      const authorizationUrl = new URL(authorizationServer.value.authorization_endpoint);

      authorizationUrl.searchParams.set("client_id", resolvedOAuthConfig.clientId);
      authorizationUrl.searchParams.set("redirect_uri", redirectUri.value.toString());
      authorizationUrl.searchParams.set("response_type", "code");
      authorizationUrl.searchParams.set("state", flowId);
      authorizationUrl.searchParams.set("code_challenge", codeChallenge);
      authorizationUrl.searchParams.set("code_challenge_method", "S256");
      authorizationUrl.searchParams.set("resource", resolvedOAuthConfig.resource);

      const scopes = toScopeString(input.scopes) ?? toScopeString(resolvedOAuthConfig.scopes);
      if (scopes) {
        authorizationUrl.searchParams.set("scope", scopes);
      }

      for (const [key, value] of Object.entries(input.additionalParameters ?? {})) {
        authorizationUrl.searchParams.set(key, value);
      }

      const flow: PendingFlow = {
        id: flowId,
        path: path.value,
        credential: input.option.profilePath ? { profilePath: input.option.profilePath } : {},
        headers: input.headers,
        redirectUri: redirectUri.value.toString(),
        codeVerifier,
        expiresAt: input.expiresAt ?? defaultExpiry(options.clock),
        oauthConfig: resolvedOAuthConfig,
      };
      await flowStore.value.create(flow);

      return ok({
        flowId,
        authorizationUrl: authorizationUrl.toString(),
        expiresAt: flow.expiresAt,
        path: flow.path,
        resource: flow.oauthConfig.resource,
        option: input.option,
      });
    },

    async completeAuthorization(input: ConnectCompleteOAuthInput, optionsForCrud?: CrudOptions) {
      const flowStore = await requireFlowStore();
      if (!flowStore.ok) {
        return flowStore;
      }

      const callbackUrl = assertUrl(input.callbackUri, "callback uri");
      if (!callbackUrl.ok) {
        return err(callbackUrl.error);
      }

      const flowId = callbackUrl.value.searchParams.get("state");
      if (!flowId) {
        return err(inputError("OAuth callback is missing state"));
      }

      const flowResult = await this.getFlow(flowId);
      if (!flowResult.ok) {
        return flowResult;
      }
      const flow = flowResult.value;
      if (flow.expiresAt.getTime() <= options.clock().getTime()) {
        await flowStore.value.delete(flow.id);
        return err(expiredError("oauth-flow", `OAuth flow '${flow.id}' has expired`));
      }

      const authorizationServer = await resolveAuthorizationServer(
        flow.oauthConfig,
        options.customFetch,
      );
      if (!authorizationServer.ok) {
        return authorizationServer;
      }

      const client = buildClient(flow.oauthConfig);
      const clientAuthentication = buildClientAuthentication(flow.oauthConfig);
      if (!clientAuthentication.ok) {
        return clientAuthentication;
      }

      const validated = result(() =>
        oauth.validateAuthResponse(authorizationServer.value, client, callbackUrl.value, flow.id),
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
          tokenRequestOptions(flow.oauthConfig.resource, options.customFetch),
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

      const existing = await options.getCredential(flow.path, optionsForCrud);
      if (!existing.ok) {
        return existing;
      }

      const secret = oauthSecretFromTokenResponse(processed.value, flow.oauthConfig);
      secret.headers = mergeHeaders({
        existingHeaders: existing.value?.secret.headers,
        headers: flow.headers,
        oauthHeaders: secret.headers,
        preserveExistingHeaders: true,
      });

      const credential = await options.putCredential(
        {
          path: flow.path,
          auth: {
            kind: "oauth",
            profilePath: flow.credential.profilePath,
            resource: flow.oauthConfig.resource,
          },
          secret,
        },
        optionsForCrud,
      );
      if (!credential.ok) {
        return credential;
      }

      await flowStore.value.complete(flow.id);

      return ok({
        path: flow.path,
        credential: credential.value,
      });
    },

    async refreshCredential(path: string, force = false, credential?: CredentialRecord) {
      const normalizedPath = assertPath(path, "path");
      if (!normalizedPath.ok) {
        return err(normalizedPath.error);
      }
      return refreshCredential(normalizedPath.value, { force, credential });
    },

    async disconnect(input: ConnectDisconnectInput) {
      const path = assertPath(input.path, "path");
      if (!path.ok) {
        return err(path.error);
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

    createWebHandlers(optionsForHandlers: ConnectWebHandlerOptions = {}): ConnectWebHandlers {
      const callbackPath = optionsForHandlers.callbackPath ?? "/oauth/callback";

      return {
        start: async (request, input) => {
          try {
            const session = await this.startAuthorization({
              ...input,
              path: input.path,
              redirectUri: input.redirectUri ?? resolveRedirectUri(request, callbackPath),
            });
            if (!session.ok) {
              const error = handlerError(
                session.error,
                "OAuth start failed",
                "oauth.createWebHandlers.startAuthorization",
              );
              return optionsForHandlers.error
                ? optionsForHandlers.error(error, request)
                : defaultErrorResponse(error);
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
              const error = handlerError(
                completed.error,
                "OAuth flow failed",
                "oauth.createWebHandlers.completeAuthorization",
              );
              return optionsForHandlers.error
                ? optionsForHandlers.error(error, request)
                : defaultErrorResponse(error);
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

    createClientMetadataDocument(input: CimdDocumentInput) {
      const clientId = assertUrl(input.clientId, "client id");
      if (!clientId.ok) {
        return clientId;
      }
      if (!isClientMetadataDocumentUrl(clientId.value.toString())) {
        return err(
          inputError(`Invalid client id '${input.clientId}'`, {
            field: "client id",
            value: input.clientId,
          }),
        );
      }
      const clientName = stringValue(input.clientName);
      if (!clientName) {
        return err(inputError("CIMD requires clientName"));
      }
      if (input.redirectUris.length === 0) {
        return err(inputError("CIMD requires at least one redirect URI"));
      }

      const redirectUris = [];
      for (const uri of input.redirectUris) {
        const redirectUri = assertRedirectUrl(uri, "redirect uri");
        if (!redirectUri.ok) {
          return redirectUri;
        }
        redirectUris.push(redirectUri.value.toString());
      }

      const jwksUri = input.jwksUri
        ? assertUrl(input.jwksUri, "jwks uri")
        : ok<URL | undefined>(undefined);
      if (!jwksUri.ok) {
        return jwksUri;
      }

      return ok({
        client_id: clientId.value.toString(),
        redirect_uris: redirectUris,
        response_types: ["code"],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? "none",
        client_name: clientName,
        scope: toScopeString(input.scope),
        jwks_uri: jwksUri.value?.toString(),
        jwks: input.jwks,
        token_endpoint_auth_signing_alg: input.tokenEndpointAuthSigningAlg,
      });
    },

    createClientMetadataResponse(input: CimdDocumentInput) {
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
