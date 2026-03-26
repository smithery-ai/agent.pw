import { afterEach, describe, expect, it, vi } from "vitest";
import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { AgentPwInputError } from "../packages/server/src/errors";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import type { ConnectOAuthOption } from "../packages/server/src/types";
import { BISCUIT_PRIVATE_KEY, createTestDb } from "./setup";

function createDiscoveryFetch(
  options: {
    authorizationServers?: string[];
    includeRegistrationEndpoint?: boolean;
  } = {},
) {
  const calls: string[] = [];
  const authorizationServers = options.authorizationServers ?? ["https://auth.example.com"];
  const includeRegistrationEndpoint = options.includeRegistrationEndpoint ?? true;

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

    if (
      url === "https://auth.example.com/.well-known/oauth-authorization-server" ||
      url === "https://auth.example.com/.well-known/openid-configuration"
    ) {
      return Response.json({
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
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
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY);
  return createAgentPw({
    db,
    encryptionKey,
    flowStore: options.flowStore,
    oauthFetch: options.oauthFetch,
    oauthClient: options.oauthClient,
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("oauth edge cases", () => {
  it("requires explicit flow storage and valid oauth options", async () => {
    const headersOnly = await createAgent();

    await expect(
      headersOnly.connect.start({
        path: "/org/connections/docs",
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

    expect(() =>
      agentPw.connect.start({
        path: "/org/connections/docs",
        option: {
          kind: "headers",
          source: "profile",
          label: "Docs",
          resource: "https://docs.example.com/mcp",
          profilePath: "/docs",
          fields: [{ name: "Authorization", label: "Token" }],
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).toThrow("connect.start requires an oauth option");

    await expect(
      agentPw.connect.start({
        path: "/org/connections/docs",
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

    await agentPw.profiles.put("/linear", {
      resourcePatterns: ["https://api.linear.app/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
      },
    });

    await expect(
      agentPw.connect.start({
        path: "/org/connections/linear",
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
  });

  it("validates missing state, unknown flows, expired flows, and profile oauth config errors", async () => {
    const flowStore = createInMemoryFlowStore();
    const agentPw = await createAgent({
      flowStore,
    });

    await expect(
      agentPw.connect.complete({
        callbackUri: "https://app.example.com/oauth/callback?code=missing",
      }),
    ).rejects.toThrow("OAuth callback is missing state");

    await expect(
      agentPw.connect.complete({
        callbackUri: "https://app.example.com/oauth/callback?code=missing&state=unknown",
      }),
    ).rejects.toThrow("Unknown OAuth flow 'unknown'");

    await flowStore.create({
      id: "expired-state",
      path: "/org/connections/docs",
      resource: "https://docs.example.com/mcp",
      option: {
        kind: "oauth",
        source: "discovery",
        label: "Docs",
        resource: "https://docs.example.com/mcp",
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
      agentPw.connect.complete({
        callbackUri: "https://app.example.com/oauth/callback?code=expired&state=expired-state",
      }),
    ).rejects.toThrow("OAuth flow 'expired-state' has expired");

    await agentPw.profiles.put("/broken", {
      resourcePatterns: ["https://api.linear.app/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
      },
    });

    await expect(
      agentPw.connect.start({
        path: "/org/connections/broken",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Broken",
          profilePath: "/missing",
          resource: "https://api.linear.app",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Credential Profile '/missing' does not exist");

    await expect(
      agentPw.connect.start({
        path: "/org/connections/broken",
        option: {
          kind: "oauth",
          source: "profile",
          label: "Broken",
          profilePath: "/broken",
          resource: "https://api.linear.app",
        },
        redirectUri: "https://app.example.com/oauth/callback",
      }),
    ).rejects.toThrow("Credential Profile '/broken' requires a clientId or default oauth client");
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
        path: "/org/connections/unconfigured",
        resource: "https://unknown.example.com",
      }),
    ).toEqual({
      kind: "options",
      options: [],
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

    await agentPw.profiles.put("/docs-api", {
      resourcePatterns: ["https://docs.example.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Bearer token", prefix: "Bearer " }],
      },
      displayName: "Docs API key",
    });

    const prepared = await agentPw.connect.prepare({
      path: "/org/connections/docs",
      resource: "https://docs.example.com/mcp",
    });
    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }
    expect(prepared.options.map((option) => option.kind)).toEqual(["oauth", "headers"]);

    await agentPw.credentials.put({
      path: "/org/connections/manual",
      resource: "https://manual.example.com",
      auth: { kind: "headers" },
      secret: { headers: { Authorization: "Bearer manual-token" } },
    });
    expect(await agentPw.connect.headers({ path: "/org/connections/manual" })).toEqual({
      Authorization: "Bearer manual-token",
    });

    await agentPw.credentials.put({
      path: "/org/connections/oauth-no-refresh",
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
    expect(await agentPw.connect.headers({ path: "/org/connections/oauth-no-refresh" })).toEqual({
      Authorization: "Bearer stale-token",
    });

    await agentPw.credentials.put({
      path: "/org/connections/oauth-no-client",
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
    expect(await agentPw.connect.headers({ path: "/org/connections/oauth-no-client" })).toEqual({
      Authorization: "Bearer stale-token-2",
    });

    await agentPw.credentials.put({
      path: "/org/connections/oauth-no-revoke",
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

    expect(await agentPw.connect.disconnect({ path: "/missing" })).toBe(false);
    expect(
      await agentPw.connect.disconnect({
        path: "/org/connections/oauth-no-revoke",
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
      path: "/org/connections/docs",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }
    const option = prepared.options.find((candidate) => candidate.kind === "oauth");
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    const handlers = agentPw.connect.createWebHandlers({
      callbackPath: "/oauth/callback",
      success(result) {
        return Response.json({ path: result.path }, { status: 201 });
      },
      error(error) {
        return Response.json(
          { error: error instanceof Error ? error.message : "unknown" },
          { status: 418 },
        );
      },
    });

    const startResponse = await handlers.start(new Request("https://app.example.com/connect"), {
      path: "/org/connections/docs",
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
    expect(await success.json()).toEqual({ path: "/org/connections/docs" });

    const failure = await handlers.callback(
      new Request("https://app.example.com/oauth/callback?code=missing"),
    );
    expect(failure.status).toBe(418);
    expect(await failure.json()).toEqual({ error: "OAuth callback is missing state" });

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "not-a-url",
        redirectUris: ["https://app.example.com/oauth/callback"],
      }),
    ).toThrow(AgentPwInputError);

    expect(() =>
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: [],
      }),
    ).toThrow("CIMD requires at least one redirect URI");

    expect(calls.some((url) => url.includes("/.well-known/oauth-protected-resource"))).toBe(true);
  });

  it("surfaces discovery option validation and dynamic registration errors", async () => {
    const missingRegistration = createDiscoveryFetch({ includeRegistrationEndpoint: false });
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
      path: "/org/connections/docs",
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
      agentPw.connect.start({
        path: "/org/connections/docs",
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
      agentWithFixedClient.connect.start({
        path: "/org/connections/docs",
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
  });
});
