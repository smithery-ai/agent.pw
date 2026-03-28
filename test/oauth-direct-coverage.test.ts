import { err, ok } from "okay-error";
import { afterEach, describe, expect, it } from "vitest";
import { createInMemoryFlowStore, createOAuthService } from "agent.pw/oauth";
import { inputError } from "../packages/server/src/errors";
import type {
  ConnectOAuthOption,
  CredentialProfileRecord,
  CredentialRecord,
  OAuthClientInput,
  OAuthResolvedConfig,
  PendingFlow,
} from "../packages/server/src/types";
import { errorOf } from "./support/results";

const NOW = new Date("2026-01-01T00:00:00.000Z");

function oauthProfile(
  path: string,
  auth: CredentialProfileRecord["auth"],
): CredentialProfileRecord {
  return {
    path,
    resourcePatterns: ["https://resource.example.com/*"],
    auth,
    displayName: null,
    description: null,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

type StoredConfig = NonNullable<CredentialRecord["secret"]["oauth"]>;

function oauthCredential(path: string, config: Partial<StoredConfig> = {}): CredentialRecord {
  const resource = config.resource ?? "https://resource.example.com";
  return {
    path,
    auth: {
      kind: "oauth",
      ...(resource ? { resource } : {}),
    },
    secret: {
      headers: { Authorization: "Bearer stale" },
      oauth: {
        accessToken: "access-token",
        refreshToken: "refresh-token",
        expiresAt: NOW.toISOString(),
        clientId: "client-id",
        clientAuthentication: "none",
        authorizationUrl: "https://issuer.example.com/authorize",
        tokenUrl: "https://issuer.example.com/token",
        ...config,
      },
    },
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function discoveryOption(input: Partial<ConnectOAuthOption> = {}): ConnectOAuthOption {
  return {
    kind: "oauth",
    source: "discovery",
    label: "OAuth",
    resource: "https://resource.example.com",
    ...input,
  };
}

function profileOption(input: Partial<ConnectOAuthOption> = {}): ConnectOAuthOption {
  return {
    kind: "oauth",
    source: "profile",
    label: "Profile OAuth",
    profilePath: "profiles.oauth",
    resource: "https://resource.example.com",
    ...input,
  };
}

function seededFlow(config: Partial<OAuthResolvedConfig> = {}): PendingFlow {
  return {
    id: "flow-1",
    path: "org.oauth",
    credential: {},
    redirectUri: "https://app.example.com/oauth/callback",
    codeVerifier: "verifier",
    expiresAt: new Date("2026-01-01T00:10:00.000Z"),
    oauthConfig: {
      clientId: "client-id",
      clientAuthentication: "none",
      authorizationUrl: "https://issuer.example.com/authorize",
      tokenUrl: "https://issuer.example.com/token",
      resource: "https://resource.example.com/",
      ...config,
    },
  };
}

function textJsonResponse(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function createFetch(overrides: Record<string, Response | Error> = {}): typeof fetch {
  const fetchImpl: typeof fetch = async (input) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const override = overrides[url];
    if (override instanceof Error) {
      throw override;
    }
    if (override) {
      return override;
    }

    if (
      url === "https://resource.example.com/.well-known/oauth-protected-resource" ||
      url === "https://docs.example.com/.well-known/oauth-protected-resource/mcp"
    ) {
      return Response.json({
        resource: url.startsWith("https://docs.example.com")
          ? "https://docs.example.com/mcp"
          : "https://resource.example.com/",
        authorization_servers: ["https://issuer.example.com"],
      });
    }

    if (
      url === "https://issuer.example.com/.well-known/oauth-authorization-server" ||
      url === "https://issuer.example.com/.well-known/openid-configuration"
    ) {
      return Response.json({
        issuer: "https://issuer.example.com",
        authorization_endpoint: "https://issuer.example.com/authorize",
        token_endpoint: "https://issuer.example.com/token",
        revocation_endpoint: "https://issuer.example.com/revoke",
        registration_endpoint: "https://issuer.example.com/register",
        code_challenge_methods_supported: ["S256"],
      });
    }

    if (url === "https://issuer.example.com/register") {
      return Response.json({ client_id: "registered-client" });
    }

    if (url === "https://issuer.example.com/token") {
      return Response.json({
        access_token: "fresh-access",
        refresh_token: "fresh-refresh",
        token_type: "Bearer",
      });
    }

    if (url === "https://issuer.example.com/revoke") {
      return new Response(null, { status: 200 });
    }

    throw new Error(`Unexpected fetch ${url}`);
  };

  return fetchImpl;
}

function createService(
  options: {
    flowStore?: ReturnType<typeof createInMemoryFlowStore>;
    customFetch?: typeof fetch;
    defaultClient?: OAuthClientInput;
    getProfile?: (path: string) => ReturnType<typeof Promise.resolve<unknown>>;
    getCredential?: (path: string) => ReturnType<typeof Promise.resolve<unknown>>;
    putCredential?: (input: unknown) => ReturnType<typeof Promise.resolve<unknown>>;
    deleteCredential?: (path: string) => ReturnType<typeof Promise.resolve<unknown>>;
  } = {},
) {
  return createOAuthService({
    flowStore: options.flowStore,
    clock: () => NOW,
    customFetch: options.customFetch,
    defaultClient: options.defaultClient,
    getProfile:
      (options.getProfile as never) ??
      (async () =>
        ok(
          oauthProfile("profiles.oauth", {
            kind: "oauth",
            issuer: "https://issuer.example.com",
            clientId: "profile-client",
          }),
        )),
    getCredential:
      (options.getCredential as never) ?? (async () => ok<CredentialRecord | null>(null)),
    putCredential:
      (options.putCredential as never) ??
      (async (input: {
        path: string;
        auth: CredentialRecord["auth"];
        secret: CredentialRecord["secret"];
      }) =>
        ok({
          path: input.path,
          auth: input.auth,
          secret: input.secret,
          createdAt: NOW,
          updatedAt: NOW,
        })),
    deleteCredential: (options.deleteCredential as never) ?? (async () => ok(true)),
  });
}

afterEach(() => {
  // No module mocks in this file.
});

describe("oauth direct coverage", () => {
  it("covers discovery and startAuthorization validation failures", async () => {
    const service = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://docs.example.com/.well-known/oauth-protected-resource/mcp": textJsonResponse("{"),
      }),
    });

    expect(errorOf(await service.discoverResource({ resource: "not-a-url" })).message).toBe(
      "Invalid resource 'not-a-url'",
    );
    expect(
      errorOf(await service.discoverResource({ resource: "https://docs.example.com/mcp" })).message,
    ).toBe("Failed to process resource metadata for 'https://docs.example.com/mcp'");

    expect(
      errorOf(
        await service.startAuthorization({
          path: "org.oauth",
          option: profileOption(),
          redirectUri: "not-a-url",
        }),
      ).message,
    ).toBe("Invalid redirect uri 'not-a-url'");

    const profileErrorService = createService({
      flowStore: createInMemoryFlowStore(),
      getProfile: async () => err(inputError("mock profile failure")),
    });
    expect(
      errorOf(
        await profileErrorService.startAuthorization({
          path: "org.oauth",
          option: profileOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock profile failure");
    expect(
      errorOf(
        await service.startAuthorization({
          path: "org.oauth",
          option: profileOption({ resource: "not-a-url" }),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");
  });

  it("covers discovery-option and dynamic registration failures", async () => {
    const defaultClient: OAuthClientInput = {
      clientId: "static-client",
      metadata: {
        clientId: "https://client.example.com/oauth/client.json",
        redirectUris: ["https://app.example.com/oauth/callback"],
      },
      useDynamicRegistration: true,
    };

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch({
            "https://issuer.example.com/.well-known/oauth-authorization-server": new Error(
              "auth discovery failed",
            ),
          }),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toContain("Authorization server discovery failed");

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch(),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption({ resource: "not-a-url" }),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch({
            "https://issuer.example.com/.well-known/oauth-authorization-server":
              textJsonResponse("{"),
          }),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Failed to process discovery response");

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch({
            "https://resource.example.com/.well-known/oauth-protected-resource": Response.json({
              resource: "https://resource.example.com/",
              authorization_servers: ["not-a-url"],
            }),
          }),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption({ authorizationServer: "not-a-url" }),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Invalid authorization server 'not-a-url'");

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch({
            "https://issuer.example.com/register": new Error("registration request failed"),
          }),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Dynamic client registration failed");

    expect(
      errorOf(
        await createService({
          flowStore: createInMemoryFlowStore(),
          customFetch: createFetch({
            "https://issuer.example.com/register": textJsonResponse("{"),
          }),
          defaultClient,
        }).startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Failed to process dynamic client registration response");
  });

  it("covers refreshCredential and completeAuthorization failure branches", async () => {
    const flowStore = createInMemoryFlowStore();
    await flowStore.create(seededFlow());

    const service = createService({
      flowStore,
      customFetch: createFetch(),
    });

    const getCredentialErrorService = createService({
      getCredential: async () => err(inputError("mock get credential failure")),
    });
    expect(errorOf(await getCredentialErrorService.refreshCredential("org.oauth")).message).toBe(
      "mock get credential failure",
    );

    const invalidStoredResource = oauthCredential("org.oauth", { resource: "not-a-url" });
    expect(await service.refreshCredential("org.oauth", true, invalidStoredResource)).toEqual({
      ok: true,
      value: invalidStoredResource,
    });

    expect(
      errorOf(
        await service.refreshCredential(
          "org.oauth",
          true,
          oauthCredential("org.oauth", { issuer: "not-a-url" }),
        ),
      ).message,
    ).toBe("Invalid oauth issuer 'not-a-url'");
    expect(
      errorOf(
        await service.refreshCredential(
          "org.oauth",
          true,
          oauthCredential("org.oauth", {
            issuer: undefined,
            authorizationUrl: "not-a-url",
          }),
        ),
      ).message,
    ).toBe("Invalid authorization url 'not-a-url'");
    expect(
      errorOf(
        await service.refreshCredential(
          "org.oauth",
          true,
          oauthCredential("org.oauth", {
            clientAuthentication: "client_secret_post",
            clientSecret: undefined,
          }),
        ),
      ).message,
    ).toBe("OAuth client_secret_post requires clientSecret");

    expect(
      errorOf(
        await createService({
          customFetch: createFetch({
            "https://issuer.example.com/token": new Error("refresh request failed"),
          }),
        }).refreshCredential("org.oauth", true, oauthCredential("org.oauth")),
      ).message,
    ).toBe("Failed to refresh credential for 'org.oauth'");

    expect(
      errorOf(
        await createService({
          customFetch: createFetch({
            "https://issuer.example.com/token": textJsonResponse("{"),
          }),
        }).refreshCredential("org.oauth", true, oauthCredential("org.oauth")),
      ).message,
    ).toBe("Failed to process refresh response for 'org.oauth'");
    expect(
      (
        await createService({
          customFetch: createFetch(),
        }).refreshCredential("org.oauth", true, {
          path: "org.oauth",
          auth: { kind: "oauth", profilePath: null },
          secret: {
            headers: { Authorization: "Bearer stale" },
            oauth: {
              accessToken: "access-token",
              refreshToken: "refresh-token",
              expiresAt: NOW.toISOString(),
              clientId: "client-id",
              clientAuthentication: "none",
              authorizationUrl: "https://issuer.example.com/authorize",
              tokenUrl: "https://issuer.example.com/token",
              resource: "https://resource.example.com",
            },
          },
          createdAt: NOW,
          updatedAt: NOW,
        })
      ).ok,
    ).toBe(true);

    expect(errorOf(await createService().getFlow("flow-1")).message).toBe(
      "OAuth flows require an explicit flowStore",
    );
    expect(
      errorOf(
        await createService().completeAuthorization({ callbackUri: "https://app.example.com" }),
      ).message,
    ).toBe("OAuth flows require an explicit flowStore");
    expect(errorOf(await service.completeAuthorization({ callbackUri: "not-a-url" })).message).toBe(
      "Invalid callback uri 'not-a-url'",
    );

    const badFlowStore = createInMemoryFlowStore();
    await badFlowStore.create(seededFlow({ issuer: "not-a-url" }));
    expect(
      errorOf(
        await createService({ flowStore: badFlowStore }).completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("Invalid oauth issuer 'not-a-url'");

    const authMethodFlowStore = createInMemoryFlowStore();
    await authMethodFlowStore.create(seededFlow({ clientAuthentication: "client_secret_post" }));
    expect(
      errorOf(
        await createService({ flowStore: authMethodFlowStore }).completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("OAuth client_secret_post requires clientSecret");

    expect(
      errorOf(
        await service.completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&error=access_denied",
        }),
      ).message,
    ).toBe("Failed to validate OAuth callback");

    expect(
      errorOf(
        await createService({
          flowStore,
          customFetch: createFetch({
            "https://issuer.example.com/token": new Error("code exchange failed"),
          }),
        }).completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("Failed to exchange authorization code");

    expect(
      errorOf(
        await createService({
          flowStore,
          customFetch: createFetch({
            "https://issuer.example.com/token": textJsonResponse("{"),
          }),
        }).completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("Failed to process authorization code response");

    const existingErrorFlowStore = createInMemoryFlowStore();
    await existingErrorFlowStore.create(seededFlow());
    const existingErrorService = createService({
      flowStore: existingErrorFlowStore,
      customFetch: createFetch(),
      getCredential: async () => err(inputError("mock existing credential failure")),
    });
    expect(
      errorOf(
        await existingErrorService.completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("mock existing credential failure");

    const putErrorFlowStore = createInMemoryFlowStore();
    await putErrorFlowStore.create(seededFlow());
    const putErrorService = createService({
      flowStore: putErrorFlowStore,
      customFetch: createFetch(),
      putCredential: async () => err(inputError("mock put failure")),
    });
    expect(
      errorOf(
        await putErrorService.completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        }),
      ).message,
    ).toBe("mock put failure");
  });

  it("covers disconnect failure branches", async () => {
    const getCredentialErrorService = createService({
      getCredential: async () => err(inputError("mock get credential failure")),
    });
    expect(errorOf(await getCredentialErrorService.disconnect({ path: "org.oauth" })).message).toBe(
      "mock get credential failure",
    );

    const invalidIssuerService = createService({
      getCredential: async () => ok(oauthCredential("org.oauth", { issuer: "not-a-url" })),
    });
    expect(errorOf(await invalidIssuerService.disconnect({ path: "org.oauth" })).message).toBe(
      "Invalid oauth issuer 'not-a-url'",
    );

    const baseCredential = oauthCredential("org.oauth", {
      revocationUrl: "https://issuer.example.com/revoke",
    });
    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Error("refresh revoke failed"),
          }),
        }).disconnect({ path: "org.oauth", revoke: "refresh_token" }),
      ).message,
    ).toBe("Failed to revoke refresh token");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Response("bad", { status: 500 }),
          }),
        }).disconnect({ path: "org.oauth", revoke: "refresh_token" }),
      ).message,
    ).toBe("Failed to process refresh token revocation");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Error("access revoke failed"),
          }),
        }).disconnect({ path: "org.oauth", revoke: "access_token" }),
      ).message,
    ).toBe("Failed to revoke access token");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Response("bad", { status: 500 }),
          }),
        }).disconnect({ path: "org.oauth", revoke: "access_token" }),
      ).message,
    ).toBe("Failed to process access token revocation");
  });

  it("covers web handler and client metadata helper errors", async () => {
    const service = createService({
      flowStore: createInMemoryFlowStore(),
    });

    service.startAuthorization = async () => err(inputError("mock start error"));
    const defaultStartError = await service
      .createWebHandlers()
      .start(new Request("https://app.example.com/connect"), {
        path: "org.oauth",
        option: profileOption(),
      });
    expect(defaultStartError.status).toBe(400);
    expect(await defaultStartError.json()).toEqual({ error: "mock start error" });

    const customStartResult = await service
      .createWebHandlers({
        error() {
          return new Response("custom-start-result", { status: 417 });
        },
      })
      .start(new Request("https://app.example.com/connect"), {
        path: "org.oauth",
        option: profileOption(),
      });
    expect(customStartResult.status).toBe(417);

    service.startAuthorization = async () => {
      throw new Error("start exploded");
    };
    const defaultThrownStart = await service
      .createWebHandlers()
      .start(new Request("https://app.example.com/connect"), {
        path: "org.oauth",
        option: profileOption(),
      });
    expect(defaultThrownStart.status).toBe(400);
    expect(await defaultThrownStart.json()).toEqual({ error: "OAuth start failed" });
    const customStartError = await service
      .createWebHandlers({
        error() {
          return new Response("custom-start", { status: 418 });
        },
      })
      .start(new Request("https://app.example.com/connect"), {
        path: "org.oauth",
        option: profileOption(),
      });
    expect(customStartError.status).toBe(418);

    let normalizedStartError: unknown;
    service.startAuthorization = async () =>
      ({ ok: false, error: new Error("result exploded") }) as never;
    const defaultNormalizedStart = await service
      .createWebHandlers({
        error(error) {
          normalizedStartError = error;
          return new Response("normalized-start", { status: 420 });
        },
      })
      .start(new Request("https://app.example.com/connect"), {
        path: "org.oauth",
        option: profileOption(),
      });
    expect(defaultNormalizedStart.status).toBe(420);
    expect(normalizedStartError).toMatchObject({
      type: "Internal",
      message: "OAuth start failed",
      source: "oauth.createWebHandlers.startAuthorization",
    });

    service.completeAuthorization = async () => {
      throw new Error("callback exploded");
    };
    const customCallbackError = await service
      .createWebHandlers({
        error() {
          return new Response("custom-callback", { status: 419 });
        },
      })
      .callback(new Request("https://app.example.com/oauth/callback?state=flow-1"));
    expect(customCallbackError.status).toBe(419);

    expect(
      errorOf(
        service.createClientMetadataDocument({
          clientId: "https://client.example.com/oauth/client.json",
          redirectUris: ["not-a-url"],
          clientName: "Connect Client",
        }),
      ).message,
    ).toBe("Invalid redirect uri 'not-a-url'");
    expect(
      errorOf(
        service.createClientMetadataDocument({
          clientId: "https://client.example.com/oauth/client.json",
          redirectUris: ["https://app.example.com/oauth/callback"],
          clientName: "Connect Client",
          jwksUri: "not-a-url",
        }),
      ).message,
    ).toBe("Invalid jwks uri 'not-a-url'");
    expect(
      errorOf(
        service.createClientMetadataDocument({
          clientId: "https://client.example.com/oauth/client.json",
          redirectUris: ["https://app.example.com/oauth/callback"],
        }),
      ).message,
    ).toBe("CIMD requires clientName");
    expect(
      errorOf(
        service.createClientMetadataResponse({
          clientId: "https://client.example.com/oauth/client.json",
          redirectUris: ["not-a-url"],
          clientName: "Connect Client",
        }),
      ).message,
    ).toBe("Invalid redirect uri 'not-a-url'");
    expect(
      errorOf(
        service.createClientMetadataDocument({
          clientId: "https://client.example.com",
          redirectUris: ["https://app.example.com/oauth/callback"],
          clientName: "Connect Client",
        }),
      ).message,
    ).toBe("Invalid client id 'https://client.example.com'");
    expect(
      errorOf(
        service.createClientMetadataDocument({
          clientId: "https://client.example.com/oauth/client.json",
          redirectUris: ["http://app.example.com/oauth/callback"],
          clientName: "Connect Client",
        }),
      ).message,
    ).toBe("Invalid redirect uri 'http://app.example.com/oauth/callback'");
  });
});
