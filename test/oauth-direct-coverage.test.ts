import { err, ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createInMemoryFlowStore, createOAuthService } from "agent.pw/oauth";
import { inputError } from "../packages/server/src/errors";
import type {
  ConnectOAuthOption,
  CredentialProfileOAuth,
  CredentialProfileRecord,
  CredentialRecord,
  OAuthClientInput,
  OAuthResolvedConfig,
  PendingFlow,
} from "../packages/server/src/types";
import { errorOf } from "./support/results";

const NOW = new Date("2026-01-01T00:00:00.000Z");

function oauthProfile(path: string, oauth: CredentialProfileOAuth): CredentialProfileRecord {
  return {
    path,
    resourcePatterns: ["https://resource.example.com/*"],
    http: null,
    oauth,
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
    ).toContain("Failed to process resource metadata for 'https://docs.example.com/mcp':");

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
    const discoveryCredentialErrorService = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch(),
      getCredential: async () => err(inputError("mock discovery credential failure")),
    });
    expect(
      errorOf(
        await discoveryCredentialErrorService.startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock discovery credential failure");
    const missingStoredClientService = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch(),
      getCredential: async () =>
        ok<CredentialRecord | null>(oauthCredential("org.oauth", { clientId: undefined })),
    });
    expect(
      errorOf(
        await missingStoredClientService.startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Resource 'https://resource.example.com' requires oauth client configuration");
    const missingAdvertisedMetadataService = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://issuer.example.com/.well-known/oauth-authorization-server": new Response(null, {
          status: 404,
        }),
        "https://issuer.example.com/.well-known/openid-configuration": new Response(null, {
          status: 404,
        }),
      }),
      getCredential: async () =>
        ok<CredentialRecord | null>(
          oauthCredential("org.oauth", {
            issuer: undefined,
            authorizationUrl: undefined,
            tokenUrl: undefined,
          }),
        ),
    });
    expect(
      errorOf(
        await missingAdvertisedMetadataService.startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Authorization server 'https://issuer.example.com' does not publish usable metadata");
    const noAdvertisedAuthorizationServerService = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://resource.example.com/.well-known/oauth-protected-resource": Response.json({
          resource: "https://resource.example.com/",
          authorization_servers: [],
        }),
      }),
      getCredential: async () => ok<CredentialRecord | null>(oauthCredential("org.oauth")),
    });
    expect(
      errorOf(
        await noAdvertisedAuthorizationServerService.startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Resource 'https://resource.example.com' does not advertise an authorization server");
    const invalidAdvertisedAuthorizationServerService = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://resource.example.com/.well-known/oauth-protected-resource": Response.json({
          resource: "https://resource.example.com/",
          authorization_servers: ["not-a-url"],
        }),
      }),
      getCredential: async () => ok<CredentialRecord | null>(oauthCredential("org.oauth")),
    });
    expect(
      errorOf(
        await invalidAdvertisedAuthorizationServerService.startAuthorization({
          path: "org.oauth",
          option: discoveryOption(),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Invalid authorization server 'not-a-url'");
    expect(
      errorOf(
        await service.startAuthorization({
          path: "org.oauth",
          option: profileOption({ resource: "not-a-url" }),
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");

    const metadataClientSession = await createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch(),
    }).startAuthorization({
      path: "org.oauth",
      option: discoveryOption(),
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        metadata: {
          clientId: "meta-client-id",
          redirectUris: ["https://app.example.com/oauth/callback"],
          tokenEndpointAuthMethod: "none",
        },
      },
    });
    expect(metadataClientSession.ok).toBe(true);
    if (metadataClientSession.ok) {
      expect(metadataClientSession.value.authorizationUrl).toContain("client_id=meta-client-id");
    }
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
    ).toContain("Failed to process discovery response:");

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
    ).toBe("Dynamic client registration failed: registration request failed");

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
    ).toContain("Failed to process dynamic client registration response:");
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
    const incompleteCredential = {
      ...oauthCredential("org.oauth", {
        resource: undefined,
        issuer: undefined,
        authorizationUrl: "not-a-url",
      }),
      auth: { kind: "oauth", profilePath: null } as const,
    };
    expect(await service.refreshCredential("org.oauth", true, incompleteCredential)).toEqual({
      ok: true,
      value: incompleteCredential,
    });
    expect(
      (
        await createService({
          customFetch: createFetch(),
        }).refreshCredential("org.oauth", true, {
          ...oauthCredential("org.oauth", {
            issuer: undefined,
            resource: undefined,
          }),
          auth: { kind: "oauth", profilePath: null },
        })
      ).ok,
    ).toBe(true);
    const fallbackFlowStore = createInMemoryFlowStore();
    await fallbackFlowStore.create(
      seededFlow({
        issuer: undefined,
        resource: undefined as never,
      }),
    );
    expect(
      (
        await createService({
          flowStore: fallbackFlowStore,
          customFetch: createFetch(),
        }).completeAuthorization({
          callbackUri: "https://app.example.com/oauth/callback?state=flow-1&code=ok",
        })
      ).ok,
    ).toBe(true);
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
    ).toContain("Failed to refresh credential for 'org.oauth':");

    expect(
      errorOf(
        await createService({
          customFetch: createFetch({
            "https://issuer.example.com/token": textJsonResponse("{"),
          }),
        }).refreshCredential("org.oauth", true, oauthCredential("org.oauth")),
      ).message,
    ).toContain("Failed to process refresh response for 'org.oauth':");
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
    await authMethodFlowStore.create(
      seededFlow({
        issuer: "https://issuer.example.com",
        clientAuthentication: "client_secret_post",
      }),
    );
    expect(
      errorOf(
        await createService({
          flowStore: authMethodFlowStore,
          customFetch: createFetch(),
        }).completeAuthorization({
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
    ).toContain("Failed to validate OAuth callback:");

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
    ).toContain("Failed to exchange authorization code:");

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
    ).toContain("Failed to process authorization code response:");

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
    ).toContain("Failed to revoke refresh token:");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Response("bad", { status: 500 }),
          }),
        }).disconnect({ path: "org.oauth", revoke: "refresh_token" }),
      ).message,
    ).toContain("Failed to process refresh token revocation:");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Error("access revoke failed"),
          }),
        }).disconnect({ path: "org.oauth", revoke: "access_token" }),
      ).message,
    ).toContain("Failed to revoke access token:");

    expect(
      errorOf(
        await createService({
          getCredential: async () => ok(baseCredential),
          customFetch: createFetch({
            "https://issuer.example.com/revoke": new Response("bad", { status: 500 }),
          }),
        }).disconnect({ path: "org.oauth", revoke: "access_token" }),
      ).message,
    ).toContain("Failed to process access token revocation:");
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

  it("accepts resource metadata with prefix-matching resource (RFC 9728bis)", async () => {
    // Metadata returns origin as resource, MCP endpoint is at /mcp subpath
    const service = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://prefix.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
          resource: "https://prefix.example.com",
          authorization_servers: ["https://issuer.example.com"],
          scopes_supported: ["read", "write"],
        }),
      }),
    });

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const discovered = await service.discoverResource({
      resource: "https://prefix.example.com/mcp",
    });
    expect(discovered.ok).toBe(true);
    if (discovered.ok) {
      expect(discovered.value.authorizationServers).toContain("https://issuer.example.com");
    }
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("accepting as prefix of"));
    warnSpy.mockRestore();
  });

  it("falls back to root metadata when subpath returns non-JSON content-type", async () => {
    const service = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://htmlmeta.example.com/.well-known/oauth-protected-resource/mcp": new Response(
          "<html>Not Found</html>",
          { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
        ),
        "https://htmlmeta.example.com/.well-known/oauth-protected-resource": Response.json({
          resource: "https://htmlmeta.example.com",
          authorization_servers: ["https://issuer.example.com"],
        }),
      }),
    });

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const discovered = await service.discoverResource({
      resource: "https://htmlmeta.example.com/mcp",
    });
    expect(discovered.ok).toBe(true);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("non-JSON content-type"));
    warnSpy.mockRestore();
  });

  it("rejects resource metadata with non-prefix resource mismatch", async () => {
    const service = createService({
      flowStore: createInMemoryFlowStore(),
      customFetch: createFetch({
        "https://other.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
          resource: "https://other.example.com/different",
          authorization_servers: ["https://issuer.example.com"],
        }),
        // Fallback URL also returns mismatched resource
        "https://other.example.com/.well-known/oauth-protected-resource": Response.json({
          resource: "https://other.example.com/different",
          authorization_servers: ["https://issuer.example.com"],
        }),
      }),
    });

    const discovered = await service.discoverResource({
      resource: "https://other.example.com/mcp",
    });
    expect(discovered.ok).toBe(false);
  });
});
