import { createAgentPw } from "agent.pw";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createInMemoryFlowStore, createOAuthService } from "agent.pw/oauth";
import type {
  CredentialProfileRecord,
  CredentialRecord,
  OAuthClientInput,
} from "../packages/server/src/types";
import { createTestDb } from "./setup";
import { must, mustAsync } from "./support/results";

const TEST_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
const openDbs: Array<{ $client?: { close?: () => Promise<void> } }> = [];

async function createState() {
  const db = await createTestDb();
  const agentPw = must(
    await createAgentPw({
      db,
      encryptionKey: TEST_ENCRYPTION_KEY,
    }),
  );
  openDbs.push(db);

  return {
    profiles: {
      set(path: string, profile: CredentialProfileRecord) {
        return mustAsync(
          agentPw.profiles.put(path, {
            resourcePatterns: profile.resourcePatterns,
            auth: profile.auth,
            ...(profile.displayName ? { displayName: profile.displayName } : {}),
            ...(profile.description ? { description: profile.description } : {}),
          }),
        );
      },
    },
    credentials: {
      set(path: string, credential: CredentialRecord) {
        const resource =
          typeof credential.resource === "string" ? credential.resource : credential.auth.resource;
        return mustAsync(
          agentPw.credentials.put({
            path,
            ...(resource ? { resource } : {}),
            auth: credential.auth,
            secret: credential.secret,
          }),
        );
      },
      get(path: string) {
        return mustAsync(agentPw.credentials.get(path));
      },
    },
    service(
      options: {
        customFetch?: typeof fetch;
        defaultClient?: OAuthClientInput;
        flowStore?: ReturnType<typeof createInMemoryFlowStore>;
        clock?: () => Date;
      } = {},
    ) {
      const service = createOAuthService({
        flowStore: options.flowStore,
        clock: options.clock ?? (() => new Date("2026-01-01T00:00:00.000Z")),
        customFetch: options.customFetch,
        defaultClient: options.defaultClient,
        getProfile: agentPw.profiles.get,
        getCredential: agentPw.credentials.get,
        putCredential: agentPw.credentials.put,
        deleteCredential: agentPw.credentials.delete,
      });
      const wrapped = { ...service, raw: service } as typeof service & { raw: typeof service };
      wrapped.discoverResource = (input) =>
        mustAsync(service.discoverResource(input)) as ReturnType<typeof wrapped.discoverResource>;
      wrapped.startAuthorization = (input) =>
        mustAsync(service.startAuthorization(input)) as ReturnType<
          typeof wrapped.startAuthorization
        >;
      wrapped.completeAuthorization = (input) =>
        mustAsync(service.completeAuthorization(input)) as ReturnType<
          typeof wrapped.completeAuthorization
        >;
      wrapped.getFlow = (flowId) =>
        mustAsync(service.getFlow(flowId)) as ReturnType<typeof wrapped.getFlow>;
      wrapped.refreshCredential = (path, force) =>
        mustAsync(service.refreshCredential(path, force)) as ReturnType<
          typeof wrapped.refreshCredential
        >;
      wrapped.disconnect = (input) =>
        mustAsync(service.disconnect(input)) as ReturnType<typeof wrapped.disconnect>;
      wrapped.createWebHandlers = service.createWebHandlers.bind(service);
      wrapped.createClientMetadataDocument = (input) =>
        must(service.createClientMetadataDocument(input)) as ReturnType<
          typeof wrapped.createClientMetadataDocument
        >;
      wrapped.createClientMetadataResponse = (input) =>
        must(service.createClientMetadataResponse(input)) as ReturnType<
          typeof wrapped.createClientMetadataResponse
        >;
      return wrapped;
    },
  };
}

afterEach(async () => {
  while (openDbs.length > 0) {
    await openDbs.pop()?.$client?.close?.();
  }
  vi.restoreAllMocks();
});

describe("oauth service coverage", () => {
  it("tries path-inserted protected resource metadata before root fallback", async () => {
    const state = await createState();
    const calls: string[] = [];

    const service = state.service({
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        calls.push(url);

        if (url === "https://docs.example.com/.well-known/oauth-protected-resource/mcp") {
          return new Response(null, { status: 404 });
        }

        if (url === "https://docs.example.com/.well-known/oauth-protected-resource") {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
          });
        }

        throw new Error(`Unexpected fetch ${url}`);
      },
    });

    await expect(
      service.discoverResource({
        resource: "https://docs.example.com/mcp",
      }),
    ).resolves.toEqual({
      resource: "https://docs.example.com/mcp",
      authorizationServers: ["https://auth.example.com"],
      resourceName: undefined,
      scopes: [],
    });
    expect(calls).toEqual([
      "https://docs.example.com/.well-known/oauth-protected-resource/mcp",
      "https://docs.example.com/.well-known/oauth-protected-resource",
    ]);
  });

  it("covers low-level validation, refresh, and default callback errors", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();

    const profileFetch: typeof fetch = async (input, init) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const body =
        init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(typeof init?.body === "string" ? init.body : undefined);

      if (
        url === "https://issuer.example.com/.well-known/oauth-authorization-server" ||
        url === "https://issuer.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://issuer.example.com",
          authorization_endpoint: "https://issuer.example.com/authorize",
          token_endpoint: "https://issuer.example.com/token",
          revocation_endpoint: "https://issuer.example.com/revoke",
          code_challenge_methods_supported: ["S256"],
        });
      }

      if (url === "https://issuer.example.com/token") {
        if (body.get("grant_type") === "refresh_token") {
          return Response.json({
            access_token: "forced-access",
            token_type: "Bearer",
          });
        }

        return Response.json({
          access_token: "auth-access",
          refresh_token: "auth-refresh",
          expires_in: 3600,
          token_type: "Bearer",
        });
      }

      if (url === "https://issuer.example.com/revoke") {
        return new Response(null, { status: 200 });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    const service = state.service({
      flowStore,
      customFetch: profileFetch,
    });

    await expect(service.refreshCredential("missing")).resolves.toBeNull();
    await expect(service.disconnect({ path: "missing" })).resolves.toBe(false);

    const handlers = service.raw.createWebHandlers();
    const defaultError = await handlers.callback(
      new Request("https://app.example.com/oauth/callback?code=missing"),
    );
    expect(defaultError.status).toBe(400);
    expect(await defaultError.json()).toEqual({ error: "OAuth callback is missing state" });

    const stringErrorService = state.service({
      flowStore,
      customFetch: profileFetch,
    });
    stringErrorService.raw.completeAuthorization = async () => {
      throw "boom";
    };
    const stringError = await stringErrorService.raw
      .createWebHandlers()
      .callback(new Request("https://app.example.com/oauth/callback?code=missing&state=any"));
    expect(stringError.status).toBe(400);
    expect(await stringError.json()).toEqual({ error: "OAuth flow failed" });

    await state.profiles.set("headers", {
      path: "headers",
      resourcePatterns: ["https://headers.example.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Token" }],
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      service.startAuthorization({
        path: "org.headers",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Headers",
          profilePath: "headers",
          resource: "https://headers.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Credential Profile 'headers' is not an OAuth profile");

    await state.profiles.set("issuer", {
      path: "issuer",
      resourcePatterns: ["https://issuer.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://issuer.example.com",
        clientId: "issuer-client",
        scopes: "read write",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const session = await service.startAuthorization({
      path: "org.issuer",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Issuer",
        profilePath: "issuer",
        resource: "https://issuer.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
    });
    expect(session.authorizationUrl).toContain("scope=read+write");

    await state.credentials.set("org.forced-refresh", {
      path: "org.forced-refresh",
      auth: { kind: "oauth", label: "Forced", resource: "https://issuer.example.com/api" },
      secret: {
        headers: { Authorization: "Bearer stale" },
        oauth: {
          accessToken: "stale",
          refreshToken: "refresh-token",
          expiresAt: "2026-01-01T00:00:00.000Z",
          scopes: "existing-scope",
          clientId: "issuer-client",
          clientAuthentication: "none",
          issuer: "https://issuer.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.refreshCredential("org.forced-refresh", true)).toEqual(
      expect.objectContaining({
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer forced-access" },
          oauth: expect.objectContaining({
            refreshToken: "refresh-token",
            expiresAt: "2026-01-01T00:00:00.000Z",
            scopes: "existing-scope",
          }),
        }),
      }),
    );

    const noExpiryCredential = await state.credentials.set("org.no-expiry", {
      path: "org.no-expiry",
      auth: { kind: "oauth", label: "No expiry", resource: "https://issuer.example.com/api" },
      secret: {
        headers: { Authorization: "Bearer same" },
        oauth: {
          accessToken: "same",
          refreshToken: "refresh",
          clientId: "issuer-client",
          clientAuthentication: "none",
          issuer: "https://issuer.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.refreshCredential("org.no-expiry")).toEqual(
      expect.objectContaining({
        path: "org.no-expiry",
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer forced-access" },
          oauth: expect.objectContaining({
            refreshToken: "refresh",
            clientId: "issuer-client",
            issuer: "https://issuer.example.com",
          }),
        }),
      }),
    );

    const legacyCredential = {
      path: "org.legacy-resource",
      resource: "https://issuer.example.com/api",
      auth: { kind: "oauth", label: "Legacy resource" },
      secret: {
        headers: { Authorization: "Bearer legacy-stale" },
        oauth: {
          accessToken: "legacy-stale",
          refreshToken: "refresh-token",
          expiresAt: "2026-01-01T00:00:00.000Z",
          scopes: "existing-scope",
          clientId: "issuer-client",
          clientAuthentication: "none",
          issuer: "https://issuer.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const storedLegacyCredential = await state.credentials.set(
      "org.legacy-resource",
      legacyCredential,
    );
    expect(await service.refreshCredential("org.legacy-resource", true)).toEqual(
      expect.objectContaining({
        path: storedLegacyCredential.path,
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer forced-access" },
          oauth: expect.objectContaining({
            accessToken: "forced-access",
            refreshToken: "refresh-token",
            scopes: "existing-scope",
          }),
        }),
      }),
    );

    const invalidExpiryCredential = await state.credentials.set("org.invalid-expiry", {
      path: "org.invalid-expiry",
      auth: { kind: "oauth", label: "Invalid expiry", resource: "https://issuer.example.com/api" },
      secret: {
        headers: { Authorization: "Bearer same-invalid" },
        oauth: {
          accessToken: "same-invalid",
          refreshToken: "refresh",
          expiresAt: "not-a-date",
          clientId: "issuer-client",
          clientAuthentication: "none",
          issuer: "https://issuer.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.refreshCredential("org.invalid-expiry")).toEqual(
      expect.objectContaining({
        path: "org.invalid-expiry",
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer forced-access" },
          oauth: expect.objectContaining({
            refreshToken: "refresh",
            clientId: "issuer-client",
            issuer: "https://issuer.example.com",
          }),
        }),
      }),
    );

    const noResourceCredential = await state.credentials.set("org.no-resource", {
      path: "org.no-resource",
      auth: { kind: "oauth", label: "No resource" },
      secret: {
        headers: { Authorization: "Bearer no-resource" },
        oauth: {
          accessToken: "no-resource",
          refreshToken: "refresh",
          clientId: "issuer-client",
          clientAuthentication: "none",
          issuer: "https://issuer.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.refreshCredential("org.no-resource", true)).toEqual(noResourceCredential);
  });

  it("discovers authorization server metadata in MCP order for root and path issuers", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();
    const calls: string[] = [];

    const fetchImpl: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      calls.push(url);

      if (url === "https://root-auth.example.com/.well-known/oauth-authorization-server") {
        return Response.json({
          issuer: "https://root-auth.example.com",
          authorization_endpoint: "https://root-auth.example.com/authorize",
          token_endpoint: "https://root-auth.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      if (url === "https://path-auth.example.com/.well-known/oauth-authorization-server/tenant") {
        return new Response("not found", { status: 404 });
      }

      if (url === "https://path-auth.example.com/.well-known/openid-configuration/tenant") {
        return new Response("not found", { status: 404 });
      }

      if (url === "https://path-auth.example.com/tenant/.well-known/openid-configuration") {
        return Response.json({
          issuer: "https://path-auth.example.com/tenant",
          authorization_endpoint: "https://path-auth.example.com/authorize",
          token_endpoint: "https://path-auth.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.profiles.set("root-auth", {
      path: "root-auth",
      resourcePatterns: ["https://root-auth.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://root-auth.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await state.profiles.set("path-auth", {
      path: "path-auth",
      resourcePatterns: ["https://path-auth.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://path-auth.example.com/tenant",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });

    const rootSession = await service.startAuthorization({
      path: "org.root-auth",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Root auth",
        profilePath: "root-auth",
        resource: "https://root-auth.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        clientId: "root-client",
      },
    });

    const pathSession = await service.startAuthorization({
      path: "org.path-auth",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Path auth",
        profilePath: "path-auth",
        resource: "https://path-auth.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        clientId: "path-client",
      },
    });

    expect(rootSession.authorizationUrl).toContain("https://root-auth.example.com/authorize");
    expect(pathSession.authorizationUrl).toContain("https://path-auth.example.com/authorize");
    expect(calls).toEqual([
      "https://root-auth.example.com/.well-known/oauth-authorization-server",
      "https://path-auth.example.com/.well-known/oauth-authorization-server/tenant",
      "https://path-auth.example.com/.well-known/openid-configuration/tenant",
      "https://path-auth.example.com/tenant/.well-known/openid-configuration",
    ]);
  });

  it("rejects profile issuers that do not publish usable metadata", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();

    const fetchImpl: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

      if (
        url === "https://missing-issuer.example.com/.well-known/oauth-authorization-server" ||
        url === "https://missing-issuer.example.com/.well-known/openid-configuration"
      ) {
        return new Response("not found", { status: 404 });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.profiles.set("missing-issuer", {
      path: "missing-issuer",
      resourcePatterns: ["https://missing-issuer.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://missing-issuer.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });

    await expect(
      service.startAuthorization({
        path: "org.missing-issuer",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Missing issuer",
          profilePath: "missing-issuer",
          resource: "https://missing-issuer.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
        client: {
          clientId: "missing-client",
        },
      }),
    ).rejects.toThrow(
      "Authorization server 'https://missing-issuer.example.com' does not publish usable metadata",
    );
  });

  it("uses global fetch for the MCP prepended OIDC fallback when no custom fetch is configured", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();
    const calls: string[] = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      calls.push(url);

      if (
        url === "https://global-path-auth.example.com/.well-known/oauth-authorization-server/tenant"
      ) {
        return new Response("not found", { status: 404 });
      }

      if (url === "https://global-path-auth.example.com/.well-known/openid-configuration/tenant") {
        return Response.json({
          issuer: "https://global-path-auth.example.com/tenant",
          authorization_endpoint: "https://global-path-auth.example.com/authorize",
          token_endpoint: "https://global-path-auth.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    }) as typeof fetch;

    try {
      await state.profiles.set("global-path-auth", {
        path: "global-path-auth",
        resourcePatterns: ["https://global-path-auth.example.com/*"],
        auth: {
          kind: "oauth",
          issuer: "https://global-path-auth.example.com/tenant",
        },
        displayName: null,
        description: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const service = state.service({
        flowStore,
      });

      const session = await service.startAuthorization({
        path: "org.global-path-auth",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Global path auth",
          profilePath: "global-path-auth",
          resource: "https://global-path-auth.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
        client: {
          clientId: "global-path-client",
        },
      });

      expect(session.authorizationUrl).toContain("https://global-path-auth.example.com/authorize");
      expect(calls).toEqual([
        "https://global-path-auth.example.com/.well-known/oauth-authorization-server/tenant",
        "https://global-path-auth.example.com/.well-known/openid-configuration/tenant",
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("covers oauth completion without refresh tokens and metadata-sourced client ids", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();

    const fetchImpl: typeof fetch = async (input, init) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const body =
        init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(typeof init?.body === "string" ? init.body : undefined);

      if (
        url === "https://issuer-meta.example.com/.well-known/oauth-authorization-server" ||
        url === "https://issuer-meta.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://issuer-meta.example.com",
          authorization_endpoint: "https://issuer-meta.example.com/authorize",
          token_endpoint: "https://issuer-meta.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      if (url === "https://issuer-meta.example.com/token") {
        if (body.get("grant_type") === "authorization_code") {
          return Response.json({
            access_token: "meta-access",
            token_type: "Bearer",
          });
        }
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.profiles.set("meta-client", {
      path: "meta-client",
      resourcePatterns: ["https://issuer-meta.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://issuer-meta.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });

    const started = await service.startAuthorization({
      path: "org.meta",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Meta",
        profilePath: "meta-client",
        resource: "https://issuer-meta.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        metadata: {
          clientId: "meta-client-id",
          redirectUris: ["https://app.example.com/oauth/callback"],
          tokenEndpointAuthMethod: "none",
        },
      },
    });
    expect(started.authorizationUrl).toContain("client_id=meta-client-id");

    const completed = await service.completeAuthorization({
      callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${started.flowId}`,
    });
    expect(completed.credential.secret).toEqual(
      expect.objectContaining({
        headers: { Authorization: "Bearer meta-access" },
        oauth: expect.objectContaining({
          accessToken: "meta-access",
          refreshToken: null,
        }),
      }),
    );
  });

  it("falls back to dynamic registration when metadata document client ids are unsupported", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();
    const calls: Array<{ url: string; body: URLSearchParams }> = [];

    const fetchImpl: typeof fetch = async (input, init) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const body =
        init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(typeof init?.body === "string" ? init.body : undefined);

      calls.push({ url, body });

      if (
        url === "https://issuer-register.example.com/.well-known/oauth-authorization-server" ||
        url === "https://issuer-register.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://issuer-register.example.com",
          authorization_endpoint: "https://issuer-register.example.com/authorize",
          token_endpoint: "https://issuer-register.example.com/token",
          registration_endpoint: "https://issuer-register.example.com/register",
          client_id_metadata_document_supported: false,
          code_challenge_methods_supported: ["S256"],
        });
      }

      if (url === "https://issuer-register.example.com/register") {
        return Response.json(
          {
            client_id: "registered-client-id",
            token_endpoint_auth_method: "none",
          },
          { status: 201 },
        );
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.profiles.set("metadata-client", {
      path: "metadata-client",
      resourcePatterns: ["https://issuer-register.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://issuer-register.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });

    const started = await service.startAuthorization({
      path: "org.metadata-doc",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Metadata client",
        profilePath: "metadata-client",
        resource: "https://issuer-register.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        clientId: "https://app.example.com/.well-known/oauth-client",
        clientAuthentication: "none",
        metadata: {
          redirectUris: ["https://app.example.com/oauth/callback"],
          clientName: "Connect Client",
          tokenEndpointAuthMethod: "none",
        },
      },
    });

    expect(started.authorizationUrl).toContain("client_id=registered-client-id");
    expect(calls.map((call) => call.url)).toContain("https://issuer-register.example.com/register");
  });

  it("surfaces profile dynamic registration failures when metadata document client ids are unsupported", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();

    const fetchImpl: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

      if (
        url === "https://issuer-register.example.com/.well-known/oauth-authorization-server" ||
        url === "https://issuer-register.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://issuer-register.example.com",
          authorization_endpoint: "https://issuer-register.example.com/authorize",
          token_endpoint: "https://issuer-register.example.com/token",
          client_id_metadata_document_supported: false,
          code_challenge_methods_supported: ["S256"],
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.profiles.set("metadata-client", {
      path: "metadata-client",
      resourcePatterns: ["https://issuer-register.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://issuer-register.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });

    await expect(
      service.startAuthorization({
        path: "org.metadata-doc",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Metadata client",
          profilePath: "metadata-client",
          resource: "https://issuer-register.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
        client: {
          clientId: "https://app.example.com/.well-known/oauth-client",
          clientAuthentication: "none",
          metadata: {
            redirectUris: ["https://app.example.com/oauth/callback"],
            clientName: "Connect Client",
            tokenEndpointAuthMethod: "none",
          },
        },
      }),
    ).rejects.toThrow(
      "Authorization server 'https://issuer-register.example.com' does not support dynamic client registration",
    );
  });

  it("covers discovery and client configuration edge cases", async () => {
    const emptyDiscovery: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

      if (url.includes("/.well-known/oauth-protected-resource")) {
        return Response.json({
          resource: "https://docs.example.com/mcp",
          authorization_servers: [],
        });
      }

      if (
        url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
        url === "https://auth.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://auth.example.com",
          token_endpoint: "https://auth.example.com/token",
        });
      }

      if (
        url === "https://override.example.com/.well-known/oauth-authorization-server" ||
        url === "https://override.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://override.example.com",
          authorization_endpoint: "https://override.example.com/authorize",
          token_endpoint: "https://override.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    const state = await createState();
    const flowStore = createInMemoryFlowStore();

    const noClientService = state.service({
      flowStore,
      customFetch: emptyDiscovery,
      defaultClient: {},
    });
    await expect(
      noClientService.startAuthorization({
        path: "org.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
        client: {},
      }),
    ).rejects.toThrow(
      "Resource 'https://docs.example.com/mcp' does not advertise an authorization server",
    );

    const noMetadataService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
            scopes_supported: "bad-shape",
          });
        }
        if (url === "https://auth.example.com/.well-known/oauth-authorization-server") {
          return Response.json({
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.example.com/authorize",
            token_endpoint: "https://auth.example.com/token",
            registration_endpoint: "https://auth.example.com/register",
            code_challenge_methods_supported: ["S256"],
          });
        }
        if (url === "https://auth.example.com/.well-known/openid-configuration") {
          return Response.json({
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.example.com/authorize",
            token_endpoint: "https://auth.example.com/token",
            registration_endpoint: "https://auth.example.com/register",
            code_challenge_methods_supported: ["S256"],
          });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
      defaultClient: { useDynamicRegistration: true },
    });
    const discovered = await noMetadataService.discoverResource({
      resource: "https://docs.example.com/mcp",
    });
    expect(discovered).toEqual({
      resource: "https://docs.example.com/mcp",
      authorizationServers: ["https://auth.example.com"],
      resourceName: undefined,
      scopes: [],
    });
    await expect(
      noMetadataService.startAuthorization({
        path: "org.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Dynamic client registration requires client metadata");

    const challengeParseFailure = await noMetadataService.raw.discoverResource({
      resource: "https://docs.example.com/mcp",
      response: new Response(null, {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer realm="docs", resource_metadata="not-a-url", scope="mcp.tools.read"',
        },
      }),
    });
    expect(challengeParseFailure.ok).toBe(false);
    if (challengeParseFailure.ok) {
      throw new Error("Expected resource challenge parse failure");
    }
    expect(challengeParseFailure.error).toEqual(
      expect.objectContaining({
        message: "Failed to parse resource challenge for 'https://docs.example.com/mcp'",
      }),
    );

    const noAuthorizationMetadataService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
          });
        }
        if (
          url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
          url === "https://auth.example.com/.well-known/openid-configuration"
        ) {
          return new Response("not found", { status: 404 });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
      defaultClient: {
        clientId: "docs-client",
        clientAuthentication: "none",
      },
    });
    await expect(
      noAuthorizationMetadataService.startAuthorization({
        path: "org.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "Authorization server 'https://auth.example.com' does not publish usable metadata",
    );

    await state.profiles.set("issuer-500", {
      path: "issuer-500",
      resourcePatterns: ["https://issuer-500.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://issuer-500.example.com",
        clientId: "issuer-500-client",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const discoveryFailureService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === "https://issuer-500.example.com/.well-known/oauth-authorization-server") {
          return new Response("boom", { status: 500 });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
    });
    await expect(
      discoveryFailureService.startAuthorization({
        path: "org.issuer-500",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Issuer 500",
          profilePath: "issuer-500",
          resource: "https://issuer-500.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "Authorization server discovery failed for 'https://issuer-500.example.com/'",
    );

    const noAdvertisedService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://docs.example.com/mcp",
          });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
    });
    expect(
      await noAdvertisedService.discoverResource({
        resource: "https://docs.example.com/mcp",
      }),
    ).toEqual({
      resource: "https://docs.example.com/mcp",
      authorizationServers: [],
      resourceName: undefined,
      scopes: [],
    });

    await state.profiles.set("broken-config", {
      path: "broken-config",
      resourcePatterns: ["https://broken.example.com/*"],
      auth: {
        kind: "oauth",
        clientId: "broken-client",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const brokenProfileService = state.service({
      flowStore,
      customFetch: emptyDiscovery,
    });
    await expect(
      brokenProfileService.startAuthorization({
        path: "org.broken",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Broken",
          profilePath: "broken-config",
          resource: "https://broken.example.com/api",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Failed to process resource metadata for 'https://broken.example.com/api'");

    await state.profiles.set("client-override", {
      path: "client-override",
      resourcePatterns: ["https://override.example.com/*"],
      auth: {
        kind: "oauth",
        issuer: "https://override.example.com",
      },
      displayName: null,
      description: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const overrideService = state.service({
      flowStore,
      customFetch: emptyDiscovery,
    });
    const overrideSession = await overrideService.startAuthorization({
      path: "org.override",
      option: {
        kind: "oauth",
        source: "profile",
        label: "Override",
        profilePath: "client-override",
        resource: "https://override.example.com/api",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      client: {
        clientId: "override-client",
        clientSecret: "override-secret",
        clientAuthentication: "client_secret_post",
      },
    });
    expect(overrideSession.authorizationUrl).toContain("client_id=override-client");

    const noIdService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
          });
        }
        if (
          url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
          url === "https://auth.example.com/.well-known/openid-configuration"
        ) {
          return Response.json({
            issuer: "https://auth.example.com",
            authorization_endpoint: "https://auth.example.com/authorize",
            token_endpoint: "https://auth.example.com/token",
            code_challenge_methods_supported: ["S256"],
          });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
      defaultClient: {},
    });
    await expect(
      noIdService.startAuthorization({
        path: "org.no-id",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
        client: {},
      }),
    ).rejects.toThrow(
      "Resource 'https://docs.example.com/mcp' requires a clientId or dynamic client registration",
    );

    const missingEndpointService = state.service({
      flowStore,
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
          });
        }
        if (
          url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
          url === "https://auth.example.com/.well-known/openid-configuration"
        ) {
          return Response.json({
            issuer: "https://auth.example.com",
            token_endpoint: "https://auth.example.com/token",
          });
        }
        throw new Error(`Unexpected fetch ${url}`);
      },
      defaultClient: {
        clientId: "docs-client",
        clientAuthentication: "none",
      },
    });
    await expect(
      missingEndpointService.startAuthorization({
        path: "org.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          authorizationServer: "https://auth.example.com",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "OAuth option for 'https://docs.example.com/mcp' is missing an authorization endpoint",
    );

    expect(
      missingEndpointService.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "Connect Client",
      }),
    ).toEqual({
      client_id: "https://app.example.com/.well-known/oauth-client",
      redirect_uris: ["https://app.example.com/oauth/callback"],
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      client_name: "Connect Client",
      scope: undefined,
      jwks_uri: undefined,
      jwks: undefined,
      token_endpoint_auth_signing_alg: undefined,
    });
  });

  it("covers client authentication errors and global revocation fetches", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("/.well-known/oauth-protected-resource")) {
        return Response.json({
          resource: "https://docs.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
        });
      }
      if (
        url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
        url === "https://auth.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          revocation_endpoint: "https://auth.example.com/revoke",
          registration_endpoint: "https://auth.example.com/register",
          code_challenge_methods_supported: ["S256"],
        });
      }
      if (url === "https://auth.example.com/register") {
        return Response.json(
          {
            client_id: "https://app.example.com/.well-known/oauth-client",
            token_endpoint_auth_method: "none",
          },
          { status: 201 },
        );
      }
      if (url === "https://auth.example.com/token") {
        return Response.json({
          access_token: "global-refresh-access",
          token_type: "Bearer",
        });
      }
      if (url === "https://auth.example.com/revoke") {
        return new Response(null, { status: 200 });
      }
      throw new Error(`Unexpected fetch ${url}`);
    };
    vi.stubGlobal("fetch", fetchImpl);

    const state = await createState();
    const service = state.service({
      flowStore: createInMemoryFlowStore(),
      defaultClient: {
        clientId: "docs-client",
        clientAuthentication: "none",
      },
    });

    await state.credentials.set("org.post", {
      path: "org.post",
      auth: { kind: "oauth", label: "Post", resource: "https://docs.example.com/mcp" },
      secret: {
        headers: { Authorization: "Bearer post" },
        oauth: {
          accessToken: "post",
          refreshToken: "post-refresh",
          clientId: "docs-client",
          clientAuthentication: "client_secret_post",
          issuer: "https://auth.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await expect(service.disconnect({ path: "org.post", revoke: "both" })).rejects.toThrow(
      "OAuth client_secret_post requires clientSecret",
    );

    await state.credentials.set("org.basic", {
      path: "org.basic",
      auth: { kind: "oauth", label: "Basic", resource: "https://docs.example.com/mcp" },
      secret: {
        headers: { Authorization: "Bearer basic" },
        oauth: {
          accessToken: "basic",
          refreshToken: "basic-refresh",
          clientId: "docs-client",
          clientAuthentication: "client_secret_basic",
          issuer: "https://auth.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await expect(service.disconnect({ path: "org.basic" })).rejects.toThrow(
      "OAuth client_secret_basic requires clientSecret",
    );

    await state.credentials.set("org.global", {
      path: "org.global",
      auth: { kind: "oauth", label: "Global", resource: "https://docs.example.com/mcp" },
      secret: {
        headers: { Authorization: "Bearer global" },
        oauth: {
          accessToken: "global",
          refreshToken: "global-refresh",
          clientId: "docs-client",
          clientAuthentication: "none",
          issuer: "https://auth.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.disconnect({ path: "org.global", revoke: "both" })).toBe(true);

    await state.credentials.set("org.global-basic", {
      path: "org.global-basic",
      auth: { kind: "oauth", label: "Global basic", resource: "https://docs.example.com/mcp" },
      secret: {
        headers: { Authorization: "Bearer global-basic" },
        oauth: {
          accessToken: "global-basic",
          refreshToken: "global-basic-refresh",
          clientId: "docs-client",
          clientSecret: "docs-secret",
          issuer: "https://auth.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.disconnect({ path: "org.global-basic", revoke: "refresh_token" })).toBe(
      true,
    );

    const dynamicService = state.service({
      flowStore: createInMemoryFlowStore(),
      defaultClient: {
        useDynamicRegistration: true,
        metadata: {
          redirectUris: ["https://app.example.com/oauth/callback"],
          jwksUri: "https://app.example.com/jwks.json",
          jwks: { keys: [] },
          tokenEndpointAuthMethod: "none",
        },
      },
    });
    const dynamicSession = await dynamicService.startAuthorization({
      path: "org.dynamic",
      option: {
        kind: "oauth",
        source: "discovery",
        label: "Docs",
        resource: "https://docs.example.com/mcp",
      },
      redirectUri: "https://app.example.com/oauth/callback",
    });
    expect(dynamicSession.authorizationUrl).toContain(
      "client_id=https%3A%2F%2Fapp.example.com%2F.well-known%2Foauth-client",
    );

    await state.credentials.set("org.global-refresh", {
      path: "org.global-refresh",
      auth: { kind: "oauth", label: "Refresh", resource: "https://docs.example.com/mcp" },
      secret: {
        headers: { Authorization: "Bearer stale-refresh" },
        oauth: {
          accessToken: "stale-refresh",
          refreshToken: "refresh-me",
          expiresAt: "2020-01-01T00:00:00.000Z",
          clientId: "docs-client",
          clientAuthentication: "none",
          issuer: "https://auth.example.com",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    expect(await service.refreshCredential("org.global-refresh", true)).toEqual(
      expect.objectContaining({
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer global-refresh-access" },
        }),
      }),
    );

    expect(
      dynamicService.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "Connect Client",
        jwksUri: "https://app.example.com/jwks.json",
        jwks: { keys: [] },
        tokenEndpointAuthSigningAlg: "EdDSA",
      }),
    ).toEqual(
      expect.objectContaining({
        jwks_uri: "https://app.example.com/jwks.json",
        jwks: { keys: [] },
        token_endpoint_auth_signing_alg: "EdDSA",
      }),
    );
  });

  it("recovers stored discovery clients and ignores mismatched resources", async () => {
    const state = await createState();
    const flowStore = createInMemoryFlowStore();
    const calls: string[] = [];

    const fetchImpl: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      calls.push(url);

      if (url.includes("/.well-known/oauth-protected-resource")) {
        return Response.json({
          resource: "https://docs.example.com/mcp",
          authorization_servers: ["https://auth.docs.example.com"],
        });
      }

      if (
        url === "https://auth.docs.example.com/.well-known/oauth-authorization-server" ||
        url === "https://auth.docs.example.com/.well-known/openid-configuration"
      ) {
        return Response.json({
          issuer: "https://auth.docs.example.com",
          authorization_endpoint: "https://auth.docs.example.com/authorize",
          token_endpoint: "https://auth.docs.example.com/token",
          code_challenge_methods_supported: ["S256"],
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    };

    await state.credentials.set("org.docs", {
      path: "org.docs",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth", label: "Docs" },
      secret: {
        headers: { Authorization: "Bearer stale" },
        oauth: {
          accessToken: "stale",
          refreshToken: "refresh",
          clientId: "stored-client",
          clientAuthentication: "none",
          resource: "https://docs.example.com/mcp",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const service = state.service({
      flowStore,
      customFetch: fetchImpl,
    });
    const session = await service.startAuthorization({
      path: "org.docs",
      option: {
        kind: "oauth",
        source: "discovery",
        label: "Docs",
        resource: "https://docs.example.com/mcp",
      },
      redirectUri: "https://app.example.com/oauth/callback",
    });
    expect(session.authorizationUrl).toContain("client_id=stored-client");
    expect(calls).toContain("https://auth.docs.example.com/.well-known/oauth-authorization-server");

    await state.credentials.set("org.docs-mismatch", {
      path: "org.docs-mismatch",
      resource: "https://other.example.com/mcp",
      auth: { kind: "oauth", label: "Docs mismatch" },
      secret: {
        headers: { Authorization: "Bearer stale" },
        oauth: {
          accessToken: "stale",
          refreshToken: "refresh",
          clientId: "wrong-client",
          clientAuthentication: "none",
          resource: "https://other.example.com/mcp",
        },
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      service.startAuthorization({
        path: "org.docs-mismatch",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "Resource 'https://docs.example.com/mcp' requires oauth client configuration",
    );
  });

  it("covers parseScopeChallenge edge cases", async () => {
    const state = await createState();
    const service = state.service({ flowStore: createInMemoryFlowStore() });

    // Non-Bearer www-authenticate
    expect(
      await service.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Basic realm="test"' },
        }),
      ),
    ).toEqual({ ok: true, value: null });

    // insufficient_scope with no scope param and no resource — returns empty scopes
    expect(
      await service.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
        }),
      ),
    ).toEqual({ ok: true, value: { resourceMetadataUrl: undefined, scopes: [] } });

    // insufficient_scope with no scope — falls back to well-known discovery via global fetch
    expect(
      await service.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
        }),
        "https://localhost:1/api",
      ),
    ).toEqual({ ok: true, value: { resourceMetadataUrl: undefined, scopes: [] } });

    // insufficient_scope with no scope and invalid resource (normalizeResource fails)
    expect(
      await service.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
        }),
        "not-a-url",
      ),
    ).toEqual({ ok: true, value: { resourceMetadataUrl: undefined, scopes: [] } });

    // insufficient_scope with no scope — metadata fetch fails
    const failingFetchService = state.service({
      flowStore: createInMemoryFlowStore(),
      customFetch: async () => {
        throw new Error("fetch failed");
      },
    });
    expect(
      await failingFetchService.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
        }),
        "https://resource.example.com/api",
      ),
    ).toEqual({ ok: true, value: { resourceMetadataUrl: undefined, scopes: [] } });

    // insufficient_scope with no scope — metadata has no scopes_supported
    const noScopesFetchService = state.service({
      flowStore: createInMemoryFlowStore(),
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/.well-known/oauth-protected-resource")) {
          return Response.json({
            resource: "https://resource.example.com/api",
            authorization_servers: ["https://auth.example.com"],
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      },
    });
    expect(
      await noScopesFetchService.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
        }),
        "https://resource.example.com/api",
      ),
    ).toEqual({ ok: true, value: { resourceMetadataUrl: undefined, scopes: [] } });

    // insufficient_scope with no scope but resource_metadata URL provided
    const metadataUrlFetchService = state.service({
      flowStore: createInMemoryFlowStore(),
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === "https://meta.example.com/resource") {
          return Response.json({
            resource: "https://resource.example.com/api",
            authorization_servers: ["https://auth.example.com"],
            scopes_supported: ["discovered.scope"],
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      },
    });
    expect(
      await metadataUrlFetchService.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: {
            "WWW-Authenticate":
              'Bearer error="insufficient_scope", resource_metadata="https://meta.example.com/resource"',
          },
        }),
        "https://resource.example.com/api",
      ),
    ).toEqual({
      ok: true,
      value: {
        resourceMetadataUrl: new URL("https://meta.example.com/resource"),
        scopes: ["discovered.scope"],
      },
    });

    // insufficient_scope with resource_metadata URL and no customFetch
    // (uses global fetch which will fail, falling back to empty scopes)
    const noFetchService = state.service({ flowStore: createInMemoryFlowStore() });
    expect(
      await noFetchService.raw.parseScopeChallenge(
        new Response(null, {
          status: 403,
          headers: {
            "WWW-Authenticate":
              'Bearer error="insufficient_scope", resource_metadata="https://localhost:1/nonexistent"',
          },
        }),
        "https://localhost:1/api",
      ),
    ).toEqual({
      ok: true,
      value: { resourceMetadataUrl: new URL("https://localhost:1/nonexistent"), scopes: [] },
    });

    // Invalid resource_metadata URL
    const invalidMetadata = await service.raw.parseScopeChallenge(
      new Response(null, {
        status: 403,
        headers: {
          "WWW-Authenticate":
            'Bearer error="insufficient_scope", scope="admin", resource_metadata="not-a-url"',
        },
      }),
    );
    expect(invalidMetadata.ok).toBe(false);
  });

  it("covers classifyResponse edge cases", async () => {
    const state = await createState();
    const service = state.service({ flowStore: createInMemoryFlowStore() });

    expect(await service.raw.classifyResponse({})).toEqual({
      ok: true,
      value: { kind: "none" },
    });

    expect(
      await service.raw.classifyResponse({
        response: new Response(null, { status: 200 }),
      }),
    ).toEqual({
      ok: true,
      value: { kind: "none" },
    });

    expect(
      await service.raw.classifyResponse({
        response: new Response(null, {
          status: 401,
          headers: { "WWW-Authenticate": 'Basic realm="test"' },
        }),
      }),
    ).toEqual({
      ok: true,
      value: { kind: "none" },
    });

    expect(
      await service.raw.classifyResponse({
        response: new Response(null, {
          status: 403,
          headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' },
        }),
      }),
    ).toEqual({
      ok: true,
      value: { kind: "none" },
    });

    expect(
      await service.raw.classifyResponse({
        response: {
          status: 401,
          headers: {
            Authorization: undefined,
            "WWW-Authenticate": 'Bearer scope="read write"',
          },
        },
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "auth-required",
        scheme: "bearer",
        scopes: ["read", "write"],
        resourceMetadataUrl: undefined,
      },
    });

    expect(
      await service.raw.classifyResponse({
        response: new Response(null, {
          status: 401,
          headers: {
            "WWW-Authenticate":
              'Bearer resource_metadata="https://meta.example.com/resource", scope="admin"',
          },
        }),
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "auth-required",
        scheme: "bearer",
        scopes: ["admin"],
        resourceMetadataUrl: new URL("https://meta.example.com/resource"),
      },
    });

    expect(
      await service.raw.classifyResponse({
        response: {
          status: 401,
          headers: {
            "WWW-Authenticate": ['Bearer resource_metadata="https://meta.example.com/resource"'],
          },
        },
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "auth-required",
        scheme: "bearer",
        scopes: [],
        resourceMetadataUrl: new URL("https://meta.example.com/resource"),
      },
    });

    expect(
      await service.raw.classifyResponse({
        response: new Response(null, {
          status: 403,
          headers: {
            "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="admin"',
          },
        }),
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "step-up",
        scheme: "bearer",
        scopes: ["admin"],
        resourceMetadataUrl: undefined,
      },
    });

    const metadataUrlFetchService = state.service({
      flowStore: createInMemoryFlowStore(),
      customFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === "https://meta.example.com/resource") {
          return Response.json({
            resource: "https://resource.example.com/api",
            authorization_servers: ["https://auth.example.com"],
            scopes_supported: ["discovered.scope"],
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      },
    });
    expect(
      await metadataUrlFetchService.raw.classifyResponse({
        resource: "https://resource.example.com/api",
        response: new Response(null, {
          status: 403,
          headers: {
            "WWW-Authenticate":
              'Bearer error="insufficient_scope", resource_metadata="https://meta.example.com/resource"',
          },
        }),
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "step-up",
        scheme: "bearer",
        scopes: ["discovered.scope"],
        resourceMetadataUrl: new URL("https://meta.example.com/resource"),
      },
    });

    const failingFetchService = state.service({
      flowStore: createInMemoryFlowStore(),
      customFetch: async () => {
        throw new Error("fetch failed");
      },
    });
    expect(
      await failingFetchService.raw.classifyResponse({
        resource: "https://resource.example.com/api",
        response: new Response(null, {
          status: 403,
          headers: {
            "WWW-Authenticate": 'Bearer error="insufficient_scope"',
          },
        }),
      }),
    ).toEqual({
      ok: true,
      value: {
        kind: "step-up",
        scheme: "bearer",
        scopes: [],
        resourceMetadataUrl: undefined,
      },
    });

    const invalidMetadata = await service.raw.classifyResponse({
      response: new Response(null, {
        status: 403,
        headers: {
          "WWW-Authenticate":
            'Bearer error="insufficient_scope", scope="admin", resource_metadata="not-a-url"',
        },
      }),
    });
    expect(invalidMetadata.ok).toBe(false);

    const invalidResourceLabel = await service.raw.classifyResponse({
      resource: "not-a-url",
      response: {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Bearer resource_metadata="not-a-url"',
        },
      },
    });
    expect(invalidResourceLabel.ok).toBe(false);
    if (invalidResourceLabel.ok) {
      throw new Error("Expected classifyResponse resource parse failure");
    }
    expect(invalidResourceLabel.error).toEqual(
      expect.objectContaining({
        message: "Failed to parse resource challenge for 'not-a-url'",
      }),
    );
  });
});
