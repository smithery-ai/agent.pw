import { err, ok, result, type Result } from "okay-error";
import * as oauth from "oauth4webapi";
import {
  identityGrantMetadataNotFound,
  identityGrantSigningFailed,
  identityGrantTokenRequestFailed,
  identityGrantTokenResponseFailed,
  inputError,
} from "./errors.js";
import {
  IDENTITY_ASSERTION_GRANT_PROFILE,
  IDENTITY_ASSERTION_JWT_TYPE,
  JWT_BEARER_GRANT_TYPE,
  createIdentityJwksDocument,
  importIdentityPrivateKey,
  signIdentityAssertion,
} from "./identity-jwt.js";
import { pairwiseIdentitySubject } from "./identity-subject.js";
import { mergeHeaders } from "./lib/connect-headers.js";
import { normalizeResource } from "./resource-patterns.js";
import type {
  ConnectClassifyResponseInput,
  ConnectClassifyResponseResult,
  ConnectIdentityGrantExchangeInput,
  ConnectIdentityGrantExchangeResult,
  IdentityGrantOptions,
  IdentityJwksResponseInput,
  IdentitySubjectInput,
} from "./types.js";
import type { AgentPwError } from "./errors.js";

export {
  IDENTITY_ASSERTION_GRANT_PROFILE,
  IDENTITY_ASSERTION_JWT_TYPE,
  JWT_BEARER_GRANT_TYPE,
  pairwiseIdentitySubject,
};

type AuthorizationServerWithGrantProfiles = oauth.AuthorizationServer & {
  authorization_grant_profiles_supported?: string[];
};
type UnsupportedIdentityGrantExchange = Extract<
  ConnectIdentityGrantExchangeResult,
  { kind: "unsupported" }
>;
type ProtectedResourceDiscovery =
  | { kind: "discovered"; resourceServer: oauth.ResourceServer }
  | UnsupportedIdentityGrantExchange;
type AuthorizationServerDiscovery =
  | { kind: "discovered"; authorizationServer: oauth.AuthorizationServer }
  | UnsupportedIdentityGrantExchange;
type SupportedAuthorizationServer =
  | { kind: "supported"; authorizationServer: AuthorizationServerWithGrantProfiles }
  | UnsupportedIdentityGrantExchange;

function customFetchOptions(customFetch: typeof fetch | undefined) {
  return customFetch ? { [oauth.customFetch]: customFetch } : undefined;
}

function tokenTypeForHeader(tokenType: string) {
  return tokenType.toLowerCase() === "bearer" ? "Bearer" : tokenType;
}

function requireClientId(
  clientId: string | undefined,
  defaultClientId: string | undefined,
  authorizationServerIssuer: string,
) {
  const resolved = clientId ?? defaultClientId;
  if (!resolved) {
    return err(
      inputError(
        `Identity grant for '${authorizationServerIssuer}' requires clientId or default oauth clientId`,
      ),
    );
  }
  return ok(resolved);
}

function hasSupport(values: readonly string[] | undefined, expected: string) {
  return Array.isArray(values) && values.includes(expected);
}

async function requestResourceMetadata(
  resource: string,
  resourceUrl: URL,
  resourceMetadataUrl: URL | undefined,
  customFetch: typeof fetch | undefined,
) {
  if (resourceMetadataUrl) {
    return result(
      (customFetch ?? fetch)(resourceMetadataUrl, {
        headers: {
          Accept: "application/json",
        },
      }),
    );
  }

  return result(oauth.resourceDiscoveryRequest(resourceUrl, customFetchOptions(customFetch)));
}

async function discoverProtectedResource(
  resource: string,
  resourceMetadataUrl: URL | undefined,
  customFetch: typeof fetch | undefined,
): Promise<Result<ProtectedResourceDiscovery, AgentPwError>> {
  const resourceUrl = result(() => new URL(resource));
  /* v8 ignore next 3 -- normalizeResource validates resource URLs before this helper is called. */
  if (!resourceUrl.ok) {
    return err(identityGrantMetadataNotFound(resource, resourceUrl.error));
  }
  const response = await requestResourceMetadata(
    resource,
    resourceUrl.value,
    resourceMetadataUrl,
    customFetch,
  );
  if (!response.ok) {
    return err(identityGrantMetadataNotFound(resource, response.error));
  }
  const processed = await result(
    oauth.processResourceDiscoveryResponse(resourceUrl.value, response.value),
  );
  if (!processed.ok) {
    return ok<ProtectedResourceDiscovery>({
      kind: "unsupported",
      reason: "metadata-not-found",
    });
  }
  return ok<ProtectedResourceDiscovery>({
    kind: "discovered",
    resourceServer: processed.value,
  });
}

async function discoverAuthorizationServer(
  issuer: string,
  customFetch: typeof fetch | undefined,
): Promise<Result<AuthorizationServerDiscovery, AgentPwError>> {
  const issuerUrl = result(() => new URL(issuer));
  if (!issuerUrl.ok) {
    return err(identityGrantMetadataNotFound(issuer, issuerUrl.error));
  }
  const response = await result(
    oauth.discoveryRequest(issuerUrl.value, {
      ...customFetchOptions(customFetch),
      algorithm: "oauth2",
    }),
  );
  if (!response.ok) {
    return err(identityGrantMetadataNotFound(issuer, response.error));
  }
  if (!response.value.ok) {
    await response.value.body?.cancel();
    return ok<AuthorizationServerDiscovery>({
      kind: "unsupported",
      reason: "oauth-metadata-not-found",
    });
  }
  const processed = await result(oauth.processDiscoveryResponse(issuerUrl.value, response.value));
  if (!processed.ok) {
    return ok<AuthorizationServerDiscovery>({
      kind: "unsupported",
      reason: "oauth-metadata-not-found",
    });
  }
  return ok<AuthorizationServerDiscovery>({
    kind: "discovered",
    authorizationServer: processed.value,
  });
}

function validateAuthorizationServer(
  authorizationServer: oauth.AuthorizationServer,
  requireGrantProfile: boolean,
): SupportedAuthorizationServer {
  const metadata: AuthorizationServerWithGrantProfiles = authorizationServer;
  if (!metadata.token_endpoint) {
    return {
      kind: "unsupported",
      reason: "authorization-server-not-found",
    };
  }
  if (!hasSupport(metadata.grant_types_supported, JWT_BEARER_GRANT_TYPE)) {
    return {
      kind: "unsupported",
      reason: "unsupported-grant-type",
    };
  }
  if (
    requireGrantProfile &&
    !hasSupport(metadata.authorization_grant_profiles_supported, IDENTITY_ASSERTION_GRANT_PROFILE)
  ) {
    return {
      kind: "unsupported",
      reason: "unsupported-grant-profile",
    };
  }
  if (
    metadata.token_endpoint_auth_methods_supported &&
    !hasSupport(metadata.token_endpoint_auth_methods_supported, "private_key_jwt")
  ) {
    return {
      kind: "unsupported",
      reason: "unsupported-client-auth-method",
    };
  }
  if (
    metadata.token_endpoint_auth_signing_alg_values_supported &&
    !hasSupport(metadata.token_endpoint_auth_signing_alg_values_supported, "RS256")
  ) {
    return {
      kind: "unsupported",
      reason: "unsupported-client-auth-signing-alg",
    };
  }
  return {
    kind: "supported",
    authorizationServer: metadata,
  };
}

async function resolveSubjectInput<TPrincipal>(
  options: IdentityGrantOptions<TPrincipal>,
  principal: TPrincipal,
  input: {
    path?: string;
    requestedResource: string;
    protectedResource: string;
    authorizationServerIssuer: string;
    scopes: readonly string[];
    resourceMetadataUrl?: URL;
  },
) {
  const subjectInput: IdentitySubjectInput<TPrincipal> = {
    principal,
    ...input,
  };
  const subject = await result(Promise.resolve(options.subject(subjectInput)));
  if (!subject.ok) {
    return err(identityGrantSigningFailed(subject.error));
  }
  const configuredClientId = typeof options.clientId === "string" ? options.clientId : undefined;
  const resolvedClientId =
    typeof options.clientId === "function"
      ? await result(Promise.resolve(options.clientId(subjectInput)))
      : ok(configuredClientId);
  if (!resolvedClientId.ok) {
    return err(identityGrantSigningFailed(resolvedClientId.error));
  }
  return ok({
    subject: subject.value,
    clientId: resolvedClientId.value,
    subjectInput,
  });
}

export function createIdentityGrantService(serviceOptions: {
  identityGrant?: IdentityGrantOptions<unknown>;
  customFetch?: typeof fetch;
  clock: () => Date;
  defaultClientId?: string;
  classifyResponse(
    input: ConnectClassifyResponseInput,
  ): Promise<Result<ConnectClassifyResponseResult, AgentPwError>>;
}) {
  return {
    createIdentityJwksDocument() {
      return createIdentityJwksDocument(serviceOptions.identityGrant);
    },

    createIdentityJwksResponse(input: IdentityJwksResponseInput = {}) {
      const document = this.createIdentityJwksDocument();
      if (!document.ok) {
        return document;
      }
      return ok(
        new Response(JSON.stringify(document.value, null, 2), {
          status: 200,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": input.cacheControl ?? "public, max-age=300",
          },
        }),
      );
    },

    async exchangeIdentityGrant<TPrincipal>(
      input: ConnectIdentityGrantExchangeInput<TPrincipal>,
    ): Promise<Result<ConnectIdentityGrantExchangeResult, AgentPwError>> {
      const identityGrant: IdentityGrantOptions<TPrincipal> | undefined =
        serviceOptions.identityGrant;
      if (!identityGrant) {
        return ok<ConnectIdentityGrantExchangeResult>({
          kind: "not_applicable",
          reason: "identity-grant-disabled",
        });
      }

      const resource = normalizeResource(input.resource);
      if (!resource.ok) {
        return resource;
      }
      const classified = await serviceOptions.classifyResponse({
        resource: resource.value,
        response: input.response,
      });
      if (!classified.ok) {
        return classified;
      }
      if (classified.value.kind === "none") {
        return ok<ConnectIdentityGrantExchangeResult>({
          kind: "not_applicable",
          reason: "not-auth-challenge",
        });
      }

      const protectedResource = await discoverProtectedResource(
        resource.value,
        classified.value.resourceMetadataUrl,
        serviceOptions.customFetch,
      );
      if (!protectedResource.ok) {
        return protectedResource;
      }
      if (protectedResource.value.kind === "unsupported") {
        return ok(protectedResource.value);
      }
      const resourceServer = protectedResource.value.resourceServer;

      const authorizationServers = resourceServer.authorization_servers ?? [];
      if (authorizationServers.length === 0) {
        return ok<ConnectIdentityGrantExchangeResult>({
          kind: "unsupported",
          reason: "authorization-server-not-found",
        });
      }
      const selectedIssuer = identityGrant.selectAuthorizationServer
        ? await result(
            Promise.resolve(
              identityGrant.selectAuthorizationServer({
                protectedResource: resourceServer.resource,
                authorizationServers,
              }),
            ),
          )
        : ok(authorizationServers[0]!);
      if (!selectedIssuer.ok) {
        return err(identityGrantMetadataNotFound(resource.value, selectedIssuer.error));
      }

      const authorizationServer = await discoverAuthorizationServer(
        selectedIssuer.value,
        serviceOptions.customFetch,
      );
      if (!authorizationServer.ok) {
        return authorizationServer;
      }
      if (authorizationServer.value.kind === "unsupported") {
        return ok(authorizationServer.value);
      }
      const discoveredAuthorizationServer = authorizationServer.value.authorizationServer;

      const supported = validateAuthorizationServer(
        discoveredAuthorizationServer,
        identityGrant.requireGrantProfile !== false,
      );
      if (supported.kind === "unsupported") {
        return ok(supported);
      }
      const supportedAuthorizationServer = supported.authorizationServer;

      const identity = await resolveSubjectInput(identityGrant, input.principal, {
        ...(input.path ? { path: input.path } : {}),
        requestedResource: resource.value,
        protectedResource: resourceServer.resource,
        authorizationServerIssuer: supportedAuthorizationServer.issuer,
        scopes: classified.value.scopes,
        ...(classified.value.resourceMetadataUrl
          ? { resourceMetadataUrl: classified.value.resourceMetadataUrl }
          : {}),
      });
      if (!identity.ok) {
        return identity;
      }
      const clientId = requireClientId(
        identity.value.clientId,
        serviceOptions.defaultClientId,
        supportedAuthorizationServer.issuer,
      );
      if (!clientId.ok) {
        return clientId;
      }

      const assertion = await signIdentityAssertion({
        options: identityGrant,
        subject: identity.value.subject,
        audience: supportedAuthorizationServer.issuer,
        clientId: clientId.value,
        protectedResource: resourceServer.resource,
        scopes: classified.value.scopes,
        now: serviceOptions.clock(),
      });
      if (!assertion.ok) {
        return assertion;
      }

      const privateKey = await importIdentityPrivateKey(identityGrant);
      if (!privateKey.ok) {
        return privateKey;
      }
      const clientAuthentication = result(() =>
        oauth.PrivateKeyJwt(privateKey.value, {
          [oauth.modifyAssertion]: (_header, payload) => {
            payload.aud = supportedAuthorizationServer.token_endpoint;
            payload.nbf = undefined;
          },
        }),
      );
      /* v8 ignore next 3 -- oauth4webapi validates the already-imported private CryptoKey synchronously. */
      if (!clientAuthentication.ok) {
        return err(identityGrantSigningFailed(clientAuthentication.error));
      }

      const client = {
        client_id: clientId.value,
      } satisfies oauth.Client;
      const tokenResponse = await result(
        oauth.genericTokenEndpointRequest(
          supportedAuthorizationServer,
          client,
          clientAuthentication.value,
          JWT_BEARER_GRANT_TYPE,
          {
            assertion: assertion.value,
          },
          customFetchOptions(serviceOptions.customFetch),
        ),
      );
      if (!tokenResponse.ok) {
        return err(
          identityGrantTokenRequestFailed(supportedAuthorizationServer.issuer, tokenResponse.error),
        );
      }
      const processed = await result(
        oauth.processGenericTokenEndpointResponse(
          supportedAuthorizationServer,
          client,
          tokenResponse.value,
        ),
      );
      if (!processed.ok) {
        return err(
          identityGrantTokenResponseFailed(supportedAuthorizationServer.issuer, processed.error),
        );
      }

      const tokenType = tokenTypeForHeader(processed.value.token_type);
      const authorization = `${tokenType} ${processed.value.access_token}`;
      return ok<ConnectIdentityGrantExchangeResult>({
        kind: "exchanged",
        authorization,
        headers: mergeHeaders({
          existingHeaders: input.headers,
          preserveExistingHeaders: true,
          oauthHeaders: {
            Authorization: authorization,
          },
        }),
        accessToken: processed.value.access_token,
        tokenType,
        ...(processed.value.expires_in ? { expiresIn: processed.value.expires_in } : {}),
        ...(processed.value.scope ? { scope: processed.value.scope } : {}),
        source: "identity-jag",
      });
    },
  };
}
