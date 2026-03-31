import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { afterEach, describe, expect, it, vi } from "vitest";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import type { ConnectOAuthOption } from "../packages/server/src/types";
import { TEST_KEY_MATERIAL, createTestDb } from "./setup";
import { must, mustAsync, wrapAgentPw } from "./support/results";

function createDiscoveryFetch(
  options: {
    authorizationServers?: string[];
    includeRegistrationEndpoint?: boolean;
    pkceMethods?: string[] | null;
  } = {},
) {
  const calls: string[] = [];
  const authorizationServers = options.authorizationServers ?? ["https://auth.example.com"];
  const includeRegistrationEndpoint = options.includeRegistrationEndpoint ?? true;
  const pkceMethods = options.pkceMethods === undefined ? ["S256"] : options.pkceMethods;

  const fetchImpl: typeof fetch = async (input) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push(url);

    if (url.includes("/.well-known/oauth-protected-resource")) {
      return Response.json({
        resource: "https://docs.example.com/mcp",
        authorization_servers: authorizationServers,
        resource_name: "Docs MCP",
        scopes_supported: ["mcp.tools.read"],
      });
    }

    if (url === "https://docs.example.com/oauth-resource-metadata") {
      return Response.json({
        resource: "https://docs.example.com/mcp",
        authorization_servers: authorizationServers,
        resource_name: "Docs MCP",
        scopes_supported: ["mcp.tools.read"],
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
        ...(pkceMethods ? { code_challenge_methods_supported: pkceMethods } : {}),
        ...(includeRegistrationEndpoint
          ? { registration_endpoint: "https://auth.example.com/register" }
          : {}),
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
        access_token: "fresh-access",
        refresh_token: "fresh-refresh",
        expires_in: 3600,
        token_type: "Bearer",
      });
    }

    throw new Error(`Unexpected fetch ${url}`);
  };

  return { fetchImpl, calls };
}

async function createAgent(
  options: {
    flowStore?: ReturnType<typeof createInMemoryFlowStore>;
    oauthFetch?: typeof fetch;
    oauthClient?: {
      clientId?: string;
      clientSecret?: string;
      clientAuthentication?: "none" | "client_secret_basic" | "client_secret_post";
      metadata?: {
        clientId?: string;
        redirectUris: string[];
        clientName?: string;
        tokenEndpointAuthMethod?:
          | "none"
          | "client_secret_basic"
          | "client_secret_post"
          | "private_key_jwt";
      };
      useDynamicRegistration?: boolean;
      initialAccessToken?: string;
    };
  } = {},
) {
  const db = await createTestDb();
  const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
  return wrapAgentPw(
    must(
      await createAgentPw({
        db,
        encryptionKey,
        flowStore: options.flowStore,
        oauthFetch: options.oauthFetch,
        oauthClient: options.oauthClient,
      }),
    ),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("oauth edge cases", () => {
  it("requires explicit flow storage and valid oauth options", async () => {
    const headersOnly = await createAgent();

    await expect(
      headersOnly.connect.startOAuth({
        path: "org.connections.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("OAuth flows require an explicit flowStore");

    const { fetchImpl } = createDiscoveryFetch();
    const agentPw = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: fetchImpl,
    });

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.docs",
        option: {
          kind: "headers",
          source: "profile",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
          profilePath: "docs",
          fields: [{ name: "Authorization", label: "Token" }],
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("connect.startOAuth requires an oauth option");

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.docs",
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

    await agentPw.profiles.put("linear", {
      resourcePatterns: ["https://api.linear.app/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
      },
    });

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.linear",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Linear",
          resource: "https://api.linear.app",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      } satisfies {
        path: string;
        option: ConnectOAuthOption;
        redirectUri: string;
      }),
    ).rejects.toThrow("Profile-backed OAuth option is missing profilePath");
  }, 10_000);

  it("uses WWW-Authenticate resource metadata and challenged scope during prepare", async () => {
    const calls: string[] = [];
    const agentPw = await createAgent({
      oauthFetch: async (input, init) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        calls.push(url);

        if (url === "https://docs.example.com/oauth-resource-metadata") {
          const headers = new Headers(init?.headers);
          if (headers.get("accept") !== "application/json") {
            return new Response("not acceptable", { status: 406 });
          }
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
            resource_name: "Docs MCP",
            scopes_supported: ["ignored.scope"],
          });
        }

        throw new Error(`Unexpected fetch ${url}`);
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
      response: {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer realm="docs", resource_metadata="https://docs.example.com/oauth-resource-metadata", scope="mcp.tools.read mcp.tools.write"',
        },
      },
    });

    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }

    const option = prepared.options.find((candidate) => candidate.kind === "oauth");
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    expect(option.scopes).toEqual(["mcp.tools.read", "mcp.tools.write"]);
    expect(calls).toEqual(["https://docs.example.com/oauth-resource-metadata"]);
  });

  it("classifies bearer challenges through public connect helpers", async () => {
    const agentPw = await createAgent({
      oauthFetch: async (input) => {
        const url =
          typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url === "https://docs.example.com/oauth-resource-metadata") {
          return Response.json({
            resource: "https://docs.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
            scopes_supported: ["mcp.tools.write"],
          });
        }

        throw new Error(`Unexpected fetch ${url}`);
      },
    });

    await expect(
      agentPw.connect.classifyResponse({
        response: {
          status: 401,
          headers: {
            "www-authenticate":
              'Bearer realm="docs", scope="mcp.tools.read", resource_metadata="https://docs.example.com/oauth-resource-metadata"',
          },
        },
      }),
    ).resolves.toEqual({
      kind: "auth-required",
      scheme: "bearer",
      scopes: ["mcp.tools.read"],
      resourceMetadataUrl: new URL("https://docs.example.com/oauth-resource-metadata"),
    });

    await expect(
      agentPw.scope({ rights: [] }).connect.classifyResponse({
        resource: "https://docs.example.com/mcp",
        response: new Response(null, {
          status: 403,
          headers: {
            "www-authenticate":
              'Bearer error="insufficient_scope", resource_metadata="https://docs.example.com/oauth-resource-metadata"',
          },
        }),
      }),
    ).resolves.toEqual({
      kind: "step-up",
      scheme: "bearer",
      scopes: ["mcp.tools.write"],
      resourceMetadataUrl: new URL("https://docs.example.com/oauth-resource-metadata"),
    });
  });

  it("does not consume the original response body while classifying challenges", async () => {
    const agentPw = await createAgent();
    const response = new Response("authorization required", {
      status: 401,
      headers: {
        "www-authenticate": 'Bearer scope="mcp.tools.read"',
      },
    });

    await expect(
      agentPw.connect.classifyResponse({
        response,
      }),
    ).resolves.toEqual({
      kind: "auth-required",
      scheme: "bearer",
      scopes: ["mcp.tools.read"],
      resourceMetadataUrl: undefined,
    });

    await expect(response.text()).resolves.toBe("authorization required");
  });

  it("falls back from non-bearer and missing resource metadata challenges", async () => {
    const { fetchImpl, calls } = createDiscoveryFetch();
    const agentPw = await createAgent({
      oauthFetch: fetchImpl,
    });

    const basicChallenge = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
      response: new Response(null, {
        status: 401,
        headers: {
          "www-authenticate": 'Basic realm="docs"',
        },
      }),
    });
    expect(basicChallenge.kind).toBe("options");
    if (basicChallenge.kind !== "options") {
      throw new Error("Expected oauth options");
    }
    const basicOption = basicChallenge.options.find((candidate) => candidate.kind === "oauth");
    if (!basicOption || basicOption.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }
    expect(basicOption.scopes).toEqual(["mcp.tools.read"]);

    const scopedChallenge = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
      response: new Response(null, {
        status: 401,
        headers: {
          "www-authenticate": 'Bearer scope="mcp.tools.write"',
        },
      }),
    });
    expect(scopedChallenge.kind).toBe("options");
    if (scopedChallenge.kind !== "options") {
      throw new Error("Expected oauth options");
    }
    const scopedOption = scopedChallenge.options.find((candidate) => candidate.kind === "oauth");
    if (!scopedOption || scopedOption.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }
    expect(scopedOption.scopes).toEqual(["mcp.tools.write"]);
    expect(
      calls.filter((url) => url.includes("/.well-known/oauth-protected-resource")),
    ).toHaveLength(2);
  });

  it("validates missing state, unknown flows, expired flows, and profile oauth config errors", async () => {
    const flowStore = createInMemoryFlowStore();
    const agentPw = await createAgent({
      flowStore,
    });

    await expect(
      agentPw.connect.completeOAuth({
        callbackUri: "https://app.example.com/oauth/callback?code=missing",
      }),
    ).rejects.toThrow("OAuth callback is missing state");

    await expect(
      agentPw.connect.completeOAuth({
        callbackUri: "https://app.example.com/oauth/callback?code=missing&state=unknown",
      }),
    ).rejects.toThrow("Unknown OAuth flow 'unknown'");

    await flowStore.create({
      id: "expired-state",
      path: "org.connections.docs",
      credential: {
        label: "Docs",
      },
      redirectUri: "https://app.example.com/oauth/callback",
      codeVerifier: "verifier",
      expiresAt: new Date("2000-01-01T00:00:00.000Z"),
      oauthConfig: {
        clientId: "client",
        clientAuthentication: "none",
        authorizationUrl: "https://auth.example.com/authorize",
        tokenUrl: "https://auth.example.com/token",
        resource: "https://docs.example.com/mcp",
      },
    });

    await expect(
      agentPw.connect.completeOAuth({
        callbackUri: "https://app.example.com/oauth/callback?code=expired&state=expired-state",
      }),
    ).rejects.toThrow("OAuth flow 'expired-state' has expired");

    await agentPw.profiles.put("broken", {
      resourcePatterns: ["https://api.linear.app/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
      },
    });

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.broken",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Broken",
          profilePath: "missing",
          resource: "https://api.linear.app",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Credential Profile 'missing' does not exist");

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.broken",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Broken",
          profilePath: "broken",
          resource: "https://api.linear.app",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Credential Profile 'broken' requires a clientId or default oauth client");
  });

  it("handles discovery fallback, refresh edge cases, and disconnect behavior", async () => {
    const failingDiscovery = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: async () => {
        throw new Error("no discovery");
      },
    });

    expect(
      await failingDiscovery.connect.prepare({
        path: "org.connections.unconfigured",
        resource: "https://unknown.example.com",
      }),
    ).toEqual({
      kind: "options",
      options: [],
      resolution: {
        canonicalResource: "https://unknown.example.com/",
        source: null,
        reason: "unconfigured",
        profilePath: null,
        option: null,
      },
    });

    const { fetchImpl } = createDiscoveryFetch();
    const agentPw = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: fetchImpl,
      oauthClient: {
        clientId: "fixed-client",
        clientAuthentication: "none",
      },
    });

    await agentPw.profiles.put("docs-api", {
      resourcePatterns: ["https://docs.example.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Bearer token", prefix: "Bearer " }],
      },
      displayName: "Docs API key",
    });

    const prepared = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
    });
    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }
    expect(prepared.options).toEqual([
      {
        kind: "headers",
        source: "profile",
        resource: "https://docs.example.com/mcp",
        profilePath: "docs-api",
        label: "Docs API key",
        fields: [{ name: "Authorization", label: "Bearer token", prefix: "Bearer " }],
      },
    ]);

    await agentPw.credentials.put({
      path: "org.connections.manual",
      resource: "https://manual.example.com",
      auth: { kind: "headers" },
      secret: { headers: { Authorization: "Bearer manual-token" } },
    });
    expect(await agentPw.connect.resolveHeaders({ path: "org.connections.manual" })).toEqual({
      Authorization: "Bearer manual-token",
    });

    await agentPw.credentials.put({
      path: "org.connections.oauth-no-refresh",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth" },
      secret: {
        headers: { Authorization: "Bearer stale-token" },
        oauth: {
          accessToken: "stale-token",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });
    expect(
      await agentPw.connect.resolveHeaders({
        path: "org.connections.oauth-no-refresh",
      }),
    ).toEqual({
      Authorization: "Bearer stale-token",
    });

    await agentPw.credentials.put({
      path: "org.connections.oauth-no-client",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth" },
      secret: {
        headers: { Authorization: "Bearer stale-token-2" },
        oauth: {
          accessToken: "stale-token-2",
          refreshToken: "refresh-token-2",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });
    expect(
      await agentPw.connect.resolveHeaders({
        path: "org.connections.oauth-no-client",
      }),
    ).toEqual({
      Authorization: "Bearer stale-token-2",
    });

    await agentPw.credentials.put({
      path: "org.connections.oauth-no-revoke",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth" },
      secret: {
        headers: { Authorization: "Bearer access" },
        oauth: {
          accessToken: "access",
          refreshToken: "refresh",
          expiresAt: "2020-01-01T00:00:00.000Z",
          clientId: "fixed-client",
          clientAuthentication: "none",
          authorizationUrl: "https://auth.example.com/authorize",
          tokenUrl: "https://auth.example.com/token",
        },
      },
    });

    expect(await agentPw.connect.disconnect({ path: "missing" })).toBe(false);
    expect(
      await agentPw.connect.disconnect({
        path: "org.connections.oauth-no-revoke",
        revoke: "both",
      }),
    ).toBe(true);
  });

  it("supports global fetch discovery, custom hosted responses, and cimd validation", async () => {
    const { fetchImpl, calls } = createDiscoveryFetch();
    vi.stubGlobal("fetch", fetchImpl);

    const agentPw = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthClient: {
        clientId: "fixed-client",
        clientAuthentication: "none",
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }
    const option = prepared.options.find((candidate) => candidate.kind === "oauth");
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    const challenged = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
      response: new Response(null, {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer resource_metadata="https://docs.example.com/oauth-resource-metadata", scope="mcp.tools.read"',
        },
      }),
    });
    expect(challenged.kind).toBe("options");
    if (challenged.kind !== "options") {
      throw new Error("Expected challenged options");
    }
    const challengedOption = challenged.options.find((candidate) => candidate.kind === "oauth");
    if (!challengedOption || challengedOption.kind !== "oauth") {
      throw new Error("Expected challenged oauth option");
    }
    expect(challengedOption.scopes).toEqual(["mcp.tools.read"]);

    const handlers = agentPw.connect.createWebHandlers({
      callbackPath: "/oauth/callback",
      success(result) {
        return Response.json({ path: result.path }, { status: 201 });
      },
      error(error) {
        return Response.json({ error: error.message }, { status: 418 });
      },
    });

    const startResponse = await handlers.start(new Request("https://app.example.com/connect"), {
      path: "org.connections.docs",
      option,
    });
    const flowId = new URL(startResponse.headers.get("location") ?? "").searchParams.get("state");
    if (!flowId) {
      throw new Error("Expected oauth state");
    }

    const success = await handlers.callback(
      new Request(`https://app.example.com/oauth/callback?code=code-123&state=${flowId}`),
    );
    expect(success.status).toBe(201);
    expect(await success.json()).toEqual({ path: "org.connections.docs" });

    const failure = await handlers.callback(
      new Request("https://app.example.com/oauth/callback?code=missing"),
    );
    expect(failure.status).toBe(418);
    expect(await failure.json()).toEqual({
      error: "OAuth callback is missing state",
    });

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "not-a-url",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "Connect Client",
      }),
    ).toThrow("Invalid client id 'not-a-url'");

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: [],
        clientName: "Connect Client",
      }),
    ).toThrow("CIMD requires at least one redirect URI");

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["https://app.example.com/oauth/callback"],
      }),
    ).toThrow("CIMD requires clientName");

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "Connect Client",
      }),
    ).toThrow("Invalid client id 'https://app.example.com'");

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["http://app.example.com/oauth/callback"],
        clientName: "Connect Client",
      }),
    ).toThrow("Invalid redirect uri 'http://app.example.com/oauth/callback'");

    expect(calls.some((url) => url.includes("/.well-known/oauth-protected-resource"))).toBe(true);
    expect(calls).toContain("https://docs.example.com/oauth-resource-metadata");
  });

  it("surfaces discovery option validation and dynamic registration errors", async () => {
    const missingRegistration = createDiscoveryFetch({
      includeRegistrationEndpoint: false,
    });
    const agentPw = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: missingRegistration.fetchImpl,
      oauthClient: {
        useDynamicRegistration: true,
        metadata: {
          redirectUris: ["https://app.example.com/oauth/callback"],
          clientName: "Connect Client",
          tokenEndpointAuthMethod: "none",
        },
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "org.connections.docs",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }
    const option = prepared.options.find((candidate) => candidate.kind === "oauth");
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    await expect(
      agentPw.connect.startOAuth({
        path: "org.connections.docs",
        option,
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "Authorization server 'https://auth.example.com' does not support dynamic client registration",
    );

    const advertised = createDiscoveryFetch();
    const agentWithFixedClient = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: advertised.fetchImpl,
      oauthClient: {
        clientId: "fixed-client",
        clientAuthentication: "none",
      },
    });

    await expect(
      agentWithFixedClient.connect.startOAuth({
        path: "org.connections.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
          authorizationServer: "https://other-auth.example.com",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow(
      "Authorization server 'https://other-auth.example.com' is not advertised for resource 'https://docs.example.com/mcp'",
    );

    const missingPkce = await createAgent({
      flowStore: createInMemoryFlowStore(),
      oauthFetch: createDiscoveryFetch({ pkceMethods: null }).fetchImpl,
      oauthClient: {
        clientId: "fixed-client",
        clientAuthentication: "none",
      },
    });

    await expect(
      missingPkce.connect.startOAuth({
        path: "org.connections.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Authorization server 'https://auth.example.com' does not support PKCE S256");

    await expect(
      agentWithFixedClient.connect.startOAuth({
        path: "org.connections.docs",
        option: {
          kind: "oauth",
          source: "discovery",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
        },
        redirectUri: "http://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Invalid redirect uri 'http://app.example.com/oauth/callback'");
  });
});
