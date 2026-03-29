import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { describe, expect, it } from "vitest";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import { TEST_KEY_MATERIAL, createTestDb } from "./setup";
import { must, mustAsync, wrapAgentPw } from "./support/results";

function createOAuthFetch() {
  const calls: Array<{
    url: string;
    body: URLSearchParams;
  }> = [];

  const fetchImpl: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const body =
      init?.body instanceof URLSearchParams
        ? init.body
        : new URLSearchParams(typeof init?.body === "string" ? init.body : undefined);

    calls.push({ url, body });

    if (url === "https://accounts.example.com/token") {
      if (body.get("grant_type") === "authorization_code") {
        return Response.json({
          access_token: "profile-access-1",
          refresh_token: "profile-refresh-1",
          expires_in: 3600,
          scope: "read write",
          token_type: "Bearer",
        });
      }

      if (body.get("grant_type") === "refresh_token") {
        return Response.json({
          access_token: "profile-access-2",
          refresh_token: "profile-refresh-2",
          expires_in: 7200,
          scope: "read write",
          token_type: "Bearer",
        });
      }
    }

    if (url === "https://accounts.example.com/revoke") {
      return new Response(null, { status: 200 });
    }

    if (
      url === "https://accounts.example.com/.well-known/oauth-authorization-server" ||
      url === "https://accounts.example.com/.well-known/openid-configuration"
    ) {
      return Response.json({
        issuer: "https://accounts.example.com",
        authorization_endpoint: "https://accounts.example.com/authorize",
        token_endpoint: "https://accounts.example.com/token",
        revocation_endpoint: "https://accounts.example.com/revoke",
        code_challenge_methods_supported: ["S256"],
      });
    }

    if (url.includes("/.well-known/oauth-protected-resource")) {
      return Response.json({
        resource: "https://docs.example.com/mcp",
        authorization_servers: ["https://auth.docs.example.com"],
        scopes_supported: ["mcp.tools.read"],
        resource_name: "Docs MCP",
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
        revocation_endpoint: "https://auth.docs.example.com/revoke",
        registration_endpoint: "https://auth.docs.example.com/register",
        code_challenge_methods_supported: ["S256"],
      });
    }

    if (url === "https://auth.docs.example.com/register") {
      return Response.json(
        {
          client_id: "https://app.example.com/.well-known/oauth-client",
          token_endpoint_auth_method: "none",
        },
        { status: 201 },
      );
    }

    if (url === "https://auth.docs.example.com/token") {
      if (body.get("grant_type") === "authorization_code") {
        return Response.json({
          access_token: "docs-access-1",
          refresh_token: "docs-refresh-1",
          expires_in: 3600,
          scope: "mcp.tools.read",
          token_type: "Bearer",
        });
      }

      if (body.get("grant_type") === "refresh_token") {
        return Response.json({
          access_token: "docs-access-2",
          refresh_token: "docs-refresh-2",
          expires_in: 3600,
          scope: "mcp.tools.read",
          token_type: "Bearer",
        });
      }
    }

    if (url === "https://auth.docs.example.com/revoke") {
      return new Response(null, { status: 200 });
    }

    throw new Error(`Unexpected oauth fetch: ${url}`);
  };

  return { fetchImpl, calls };
}

async function createOAuthAgent() {
  const db = await createTestDb();
  const flowStore = createInMemoryFlowStore();
  const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
  const { fetchImpl, calls } = createOAuthFetch();
  const agentPw = wrapAgentPw(
    must(
      await createAgentPw({
        db,
        encryptionKey,
        flowStore,
        oauthFetch: fetchImpl,
        oauthClient: {
          useDynamicRegistration: true,
          metadata: {
            redirectUris: ["https://app.example.com/oauth/callback"],
            clientName: "Connect Client",
            tokenEndpointAuthMethod: "none",
          },
        },
      }),
    ),
  );

  await agentPw.profiles.put("linear", {
    resourcePatterns: ["https://api.linear.app/*"],
    auth: {
      kind: "oauth",
      issuer: "https://accounts.example.com",
      clientId: "client-linear",
      clientSecret: "secret-linear",
      clientAuthentication: "client_secret_post",
      scopes: ["read", "write"],
    },
    displayName: "Linear",
  });

  return { agentPw, calls, db };
}

async function completeProfileOAuth() {
  const { agentPw, calls } = await createOAuthAgent();

  const prepared = await agentPw.connect.prepare({
    path: "org_alpha.connections.linear_1",
    resource: "https://api.linear.app/projects",
  });
  if (prepared.kind !== "options") {
    throw new Error("Expected oauth options");
  }

  const session = await agentPw.connect.startOAuth({
    path: "org_alpha.connections.linear_1",
    option: prepared.options[0]!,
    redirectUri: "https://app.example.com/oauth/callback",
  });

  const completed = await agentPw.connect.completeOAuth({
    callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${session.flowId}`,
  });

  return { agentPw, calls, completed };
}

describe("oauth runtime", () => {
  it("runs profile-backed oauth end to end and refreshes stale credentials", async () => {
    const { agentPw, calls } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.linear_1",
      resource: "https://api.linear.app/projects",
    });
    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }

    const option = prepared.options[0];
    expect(option).toEqual(
      expect.objectContaining({
        kind: "oauth",
        source: "profile",
        profilePath: "linear",
        label: "Linear",
      }),
    );

    const session = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.linear_1",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    });

    expect(session.flowId).toHaveLength(96);
    expect(session.authorizationUrl).toContain("https://accounts.example.com/authorize");
    expect(session.authorizationUrl).toContain("client_id=client-linear");
    expect(session.authorizationUrl).toContain("resource=https%3A%2F%2Fapi.linear.app%2Fprojects");

    const completed = await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${session.flowId}`,
    });

    expect(completed.path).toBe("org_alpha.connections.linear_1");
    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: "linear",
      resource: "https://api.linear.app/projects",
    });
    expect(completed.credential.secret).toEqual(
      expect.objectContaining({
        headers: { Authorization: "Bearer profile-access-1" },
        oauth: expect.objectContaining({
          accessToken: "profile-access-1",
          refreshToken: "profile-refresh-1",
          clientId: "client-linear",
          clientSecret: "secret-linear",
        }),
      }),
    );
    expect(await agentPw.credentials.get(completed.path)).toEqual(
      expect.objectContaining({
        path: completed.path,
        auth: completed.credential.auth,
        secret: expect.objectContaining({
          headers: { Authorization: "Bearer profile-access-1" },
        }),
      }),
    );

    await agentPw.credentials.put({
      path: completed.path,
      resource: completed.credential.auth.resource,
      auth: completed.credential.auth,
      secret: {
        ...completed.credential.secret,
        headers: { Authorization: "Bearer stale" },
        oauth: {
          ...completed.credential.secret.oauth,
          accessToken: "stale",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });

    expect(await agentPw.connect.resolveHeaders({ path: completed.path })).toEqual({
      Authorization: "Bearer profile-access-2",
    });
    expect(
      await agentPw.connect.disconnect({
        path: completed.path,
        revoke: "both",
      }),
    ).toBe(true);

    const profileTokenCalls = calls.filter(
      (call) => call.url === "https://accounts.example.com/token",
    );
    expect(profileTokenCalls).toHaveLength(2);
    expect(profileTokenCalls[0]?.body.get("resource")).toBe("https://api.linear.app/projects");
    expect(profileTokenCalls[1]?.body.get("resource")).toBe("https://api.linear.app/projects");
    expect(calls.map((call) => call.url)).toEqual(
      expect.arrayContaining([
        "https://accounts.example.com/token",
        "https://accounts.example.com/revoke",
      ]),
    );
  });

  it("runs discovery-first oauth, hosted handlers, and cimd helpers", async () => {
    const { agentPw, calls } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.docs_mcp",
      resource: "https://docs.example.com/mcp",
    });

    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected discovery options");
    }

    const oauthOption = prepared.options.find(
      (option) => option.kind === "oauth" && option.source === "discovery",
    );
    if (!oauthOption || oauthOption.kind !== "oauth") {
      throw new Error("Expected discovery-backed oauth option");
    }

    const session = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.docs_mcp",
      option: oauthOption,
      redirectUri: "https://app.example.com/oauth/callback",
      additionalParameters: { prompt: "consent" },
    });

    expect(session.authorizationUrl).toContain("https://auth.docs.example.com/authorize");
    expect(session.authorizationUrl).toContain(
      "client_id=https%3A%2F%2Fapp.example.com%2F.well-known%2Foauth-client",
    );
    expect(session.authorizationUrl).toContain("prompt=consent");

    const completed = await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-456&state=${session.flowId}`,
    });

    expect(completed.credential.auth.resource).toBe("https://docs.example.com/mcp");
    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: null,
      resource: "https://docs.example.com/mcp",
    });

    const handlers = agentPw.connect.createWebHandlers({
      callbackPath: "/oauth/callback",
    });
    const startResponse = await handlers.start(new Request("https://app.example.com/connect"), {
      path: "org_alpha.connections.docs_mcp_next",
      option: oauthOption,
    });
    expect(startResponse.status).toBe(302);

    const callbackState = new URL(startResponse.headers.get("location") ?? "").searchParams.get(
      "state",
    );
    const callbackResponse = await handlers.callback(
      new Request(`https://app.example.com/oauth/callback?code=code-789&state=${callbackState}`),
    );
    expect(callbackResponse.status).toBe(200);
    expect(await callbackResponse.text()).toContain("Authorization complete");

    expect(
      agentPw.connect.createClientMetadataDocument({
        clientId: "https://app.example.com/.well-known/oauth-client",
        redirectUris: ["https://app.example.com/oauth/callback"],
        clientName: "Connect Client",
        scope: ["mcp.tools.read"],
        tokenEndpointAuthMethod: "none",
      }),
    ).toEqual({
      client_id: "https://app.example.com/.well-known/oauth-client",
      redirect_uris: ["https://app.example.com/oauth/callback"],
      response_types: ["code"],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      client_name: "Connect Client",
      scope: "mcp.tools.read",
      jwks_uri: undefined,
      jwks: undefined,
      token_endpoint_auth_signing_alg: undefined,
    });

    const cimdResponse = agentPw.connect.createClientMetadataResponse({
      clientId: "https://app.example.com/.well-known/oauth-client",
      redirectUris: ["https://app.example.com/oauth/callback"],
      clientName: "Connect Client",
      scope: ["mcp.tools.read"],
      tokenEndpointAuthMethod: "none",
    });
    expect(cimdResponse.status).toBe(200);
    expect(cimdResponse.headers.get("cache-control")).toBe("public, max-age=300");
    expect(calls.map((call) => call.url)).toEqual(
      expect.arrayContaining([
        "https://auth.docs.example.com/register",
        "https://auth.docs.example.com/token",
      ]),
    );
  });

  it("stores pending oauth flows until oauth completion", async () => {
    const { agentPw } = await createOAuthAgent();

    await agentPw.profiles.put("docs", {
      resourcePatterns: ["https://docs.example.com/mcp"],
      auth: {
        kind: "oauth",
        issuer: "https://accounts.example.com",
        clientId: "client-docs",
        clientSecret: "secret-docs",
        clientAuthentication: "client_secret_post",
        scopes: ["docs.read"],
      },
      displayName: "Docs Profile",
    });

    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.docs_profiled",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected authorization options");
    }

    expect(prepared.resolution).toEqual({
      canonicalResource: "https://docs.example.com/mcp",
      source: "profile",
      reason: "matched-profile",
      profilePath: "docs",
      option: {
        kind: "oauth",
        source: "profile",
        resource: "https://docs.example.com/mcp",
        profilePath: "docs",
        label: "Docs Profile",
        scopes: ["docs.read"],
      },
    });
    const started = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.docs_profiled",
      option: prepared.options[0],
      redirectUri: "https://app.example.com/oauth/callback",
    });

    expect(started.authorizationUrl).toContain("https://accounts.example.com/authorize");

    expect(await agentPw.connect.getFlow(started.flowId)).toEqual({
      flowId: started.flowId,
      path: "org_alpha.connections.docs_profiled",
      resource: "https://docs.example.com/mcp",
      profilePath: "docs",
      expiresAt: started.expiresAt,
    });

    const completed = await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-999&state=${started.flowId}`,
    });

    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: "docs",
      resource: "https://docs.example.com/mcp",
    });
    await expect(agentPw.connect.getFlow(started.flowId)).rejects.toThrow(
      `Unknown OAuth flow '${started.flowId}'`,
    );
  });

  it("preserves existing non-auth headers and applies start headers during oauth completion", async () => {
    const { agentPw } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.linear_merge",
      resource: "https://api.linear.app/projects",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }
    const option = prepared.options[0];

    await agentPw.credentials.put({
      path: "org_alpha.connections.linear_merge",
      resource: "https://api.linear.app/projects",
      auth: {
        kind: "headers",
        profilePath: null,
        label: "Existing",
      },
      secret: {
        headers: {
          Authorization: "Bearer stale",
          "X-Smithery-Connection": "conn_123",
          "X-Trace-Id": "trace_existing",
        },
      },
    });

    const session = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.linear_merge",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
      headers: {
        Authorization: "Bearer ignored",
        "Proxy-Authorization": "Bearer ignored-proxy",
        "X-Smithery-Connection": "conn_456",
      },
    });

    const completed = await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-merge&state=${session.flowId}`,
    });

    expect(completed.credential.secret.headers).toEqual({
      Authorization: "Bearer profile-access-1",
      "X-Smithery-Connection": "conn_456",
      "X-Trace-Id": "trace_existing",
    });

    await agentPw.credentials.put({
      path: completed.path,
      resource: completed.credential.auth.resource,
      auth: completed.credential.auth,
      secret: {
        ...completed.credential.secret,
        headers: {
          ...completed.credential.secret.headers,
          Authorization: "Bearer stale-refresh",
        },
        oauth: {
          ...completed.credential.secret.oauth,
          accessToken: "stale-refresh",
          expiresAt: "2020-01-01T00:00:00.000Z",
        },
      },
    });

    expect(await agentPw.connect.resolveHeaders({ path: completed.path })).toEqual({
      Authorization: "Bearer profile-access-2",
      "X-Smithery-Connection": "conn_456",
      "X-Trace-Id": "trace_existing",
    });
  });

  it("overwrites app headers on existing oauth credentials without replacing oauth state", async () => {
    const { agentPw } = await createOAuthAgent();

    await agentPw.credentials.put({
      path: "org_alpha.connections.linear_runtime_headers",
      resource: "https://api.linear.app/projects",
      auth: {
        kind: "oauth",
        profilePath: "linear",
        label: "Linear",
        resource: "https://api.linear.app/projects",
      },
      secret: {
        headers: {
          Authorization: "Bearer profile-access-1",
          "X-Trace-Id": "trace_existing",
        },
        oauth: {
          accessToken: "profile-access-1",
          refreshToken: "profile-refresh-1",
        },
      },
    });

    const merged = await agentPw.connect.setHeaders({
      path: "org_alpha.connections.linear_runtime_headers",
      headers: {
        Authorization: "Bearer ignored",
        "X-Smithery-Connection": "conn_123",
      },
    });

    expect(merged.auth).toEqual({
      kind: "oauth",
      profilePath: "linear",
      resource: "https://api.linear.app/projects",
    });
    expect(merged.secret.headers).toEqual({
      Authorization: "Bearer profile-access-1",
      "X-Smithery-Connection": "conn_123",
    });
    expect(merged.secret.oauth).toEqual({
      accessToken: "profile-access-1",
      refreshToken: "profile-refresh-1",
    });
  });

  it("uses the caller db for connect.completeOAuth", async () => {
    const { agentPw, db } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.linear_tx",
      resource: "https://api.linear.app/projects",
    });
    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }

    const option = prepared.options[0];
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    const session = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.linear_tx",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    });

    await expect(
      db.transaction(async (tx) => {
        const completed = await agentPw.connect.completeOAuth(
          {
            callbackUri: `https://app.example.com/oauth/callback?code=code-tx&state=${session.flowId}`,
          },
          { db: tx },
        );

        expect(completed.path).toBe("org_alpha.connections.linear_tx");
        expect(await agentPw.credentials.get(completed.path, { db: tx })).toEqual(
          expect.objectContaining({
            path: "org_alpha.connections.linear_tx",
          }),
        );

        throw new Error("rollback completeOAuth tx");
      }),
    ).rejects.toThrow("rollback completeOAuth tx");

    expect(await agentPw.credentials.get("org_alpha.connections.linear_tx")).toBe(null);
  });

  it("reauthorizes legacy discovery credentials without storing discovered endpoints", async () => {
    const db = await createTestDb();
    const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
    const { fetchImpl } = createOAuthFetch();
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey,
          flowStore: createInMemoryFlowStore(),
          oauthFetch: fetchImpl,
        }),
      ),
    );

    await agentPw.credentials.put({
      path: "org_alpha.connections.docs_legacy",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth" },
      secret: {
        headers: { Authorization: "Bearer legacy-access" },
        oauth: {
          accessToken: "legacy-access",
          refreshToken: "legacy-refresh",
          clientId: "legacy-client",
          clientAuthentication: "none",
          resource: "https://docs.example.com/mcp",
        },
      },
    });

    const started = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.docs_legacy",
      option: {
        kind: "oauth",
        source: "discovery",
        label: "Docs MCP",
        resource: "https://docs.example.com/mcp",
      },
      redirectUri: "https://app.example.com/oauth/callback",
    });
    expect(started.authorizationUrl).toContain("client_id=legacy-client");

    const completed = await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-legacy&state=${started.flowId}`,
    });
    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: null,
      resource: "https://docs.example.com/mcp",
    });
    expect(completed.credential.secret.oauth).toEqual(
      expect.objectContaining({
        accessToken: "docs-access-1",
        refreshToken: "docs-refresh-1",
        clientId: "legacy-client",
        issuer: "https://auth.docs.example.com",
      }),
    );
    expect(completed.credential.secret.oauth.authorizationUrl).toBeUndefined();
    expect(completed.credential.secret.oauth.tokenUrl).toBeUndefined();
    expect(completed.credential.secret.oauth.revocationUrl).toBeUndefined();
    expect(await agentPw.profiles.get("org_alpha.connections.docs_legacy.oauth")).toBe(null);
  });

  it("force-refreshes via resolveHeaders even when token is not expired", async () => {
    const { agentPw, calls, completed } = await completeProfileOAuth();

    // Set expiresAt far in the future — normal refresh would skip this
    await agentPw.credentials.put({
      path: completed.path,
      resource: completed.credential.auth.resource,
      auth: completed.credential.auth,
      secret: {
        ...completed.credential.secret,
        headers: { Authorization: "Bearer still-valid" },
        oauth: {
          ...completed.credential.secret.oauth,
          accessToken: "still-valid",
          expiresAt: "2099-01-01T00:00:00.000Z",
        },
      },
    });

    // Normal resolve should return the existing token (not expired)
    expect(await agentPw.connect.resolveHeaders({ path: completed.path })).toEqual({
      Authorization: "Bearer still-valid",
    });

    const callsBefore = calls.length;

    // Force resolve should trigger a refresh despite valid expiresAt
    expect(
      await agentPw.connect.resolveHeaders({ path: completed.path, refresh: "force" }),
    ).toEqual({
      Authorization: "Bearer profile-access-2",
    });

    // Verify a token request was actually made
    const refreshCalls = calls.slice(callsBefore);
    expect(refreshCalls.some((c) => c.body.get("grant_type") === "refresh_token")).toBe(true);
  });

  it("refreshes tokens with missing expiresAt on normal resolveHeaders", async () => {
    const { agentPw, completed } = await completeProfileOAuth();

    // Remove expiresAt — simulates old/migrated credential
    await agentPw.credentials.put({
      path: completed.path,
      resource: completed.credential.auth.resource,
      auth: completed.credential.auth,
      secret: {
        ...completed.credential.secret,
        headers: { Authorization: "Bearer unknown-expiry" },
        oauth: {
          ...completed.credential.secret.oauth,
          accessToken: "unknown-expiry",
          expiresAt: undefined,
        },
      },
    });

    // Normal resolve should attempt refresh since expiresAt is unknown
    expect(await agentPw.connect.resolveHeaders({ path: completed.path })).toEqual({
      Authorization: "Bearer profile-access-2",
    });
  });

  it("returns step-up options with merged scopes on 403 insufficient_scope", async () => {
    const { agentPw, completed } = await completeProfileOAuth();

    const response403 = new Response(null, {
      status: 403,
      headers: {
        "WWW-Authenticate":
          'Bearer error="insufficient_scope", scope="read write admin", resource_metadata="https://api.linear.app/.well-known/oauth-protected-resource"',
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: completed.path,
      resource: "https://api.linear.app/projects",
      response: response403,
    });

    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") throw new Error("Expected options");

    expect(prepared.resolution.reason).toBe("step-up");
    expect(prepared.options).toHaveLength(1);

    const option = prepared.options[0]!;
    expect(option.kind).toBe("oauth");
    if (option.kind !== "oauth") throw new Error("Expected oauth option");

    // Existing scopes ("read write") merged with challenged scopes ("read write admin")
    expect(option.scopes).toEqual(expect.arrayContaining(["read", "write", "admin"]));
    expect(option.scopes).toHaveLength(3);

    // Should preserve profile source
    expect(option.source).toBe("profile");
    expect(option.profilePath).toBe("linear");
  });

  it("returns ready for non-insufficient_scope 403 responses", async () => {
    const { agentPw, completed } = await completeProfileOAuth();

    // 403 without insufficient_scope error
    const response403 = new Response(null, {
      status: 403,
      headers: {
        "WWW-Authenticate": 'Bearer error="invalid_token"',
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: completed.path,
      resource: "https://api.linear.app/projects",
      response: response403,
    });

    // Should still return ready since it's not insufficient_scope
    expect(prepared.kind).toBe("ready");
  });

  it("returns ready for headers credentials even with 403 insufficient_scope", async () => {
    const { agentPw } = await createOAuthAgent();

    await agentPw.connect.setHeaders({
      path: "acme.connections.api_key",
      resource: "https://api.headers-only.com",
      headers: { Authorization: "Bearer static-key" },
    });

    const response403 = new Response(null, {
      status: 403,
      headers: {
        "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="admin"',
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "acme.connections.api_key",
      resource: "https://api.headers-only.com",
      response: response403,
    });

    // Headers credentials don't support step-up — return ready
    expect(prepared.kind).toBe("ready");
  });

  it("returns step-up options for discovery-backed credentials without profile", async () => {
    const { agentPw } = await createOAuthAgent();

    // Create a discovery-backed credential (no profile)
    const prepared = await agentPw.connect.prepare({
      path: "org_alpha.connections.docs_mcp",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") throw new Error("Expected options");
    const option = prepared.options.find((o) => o.kind === "oauth")!;

    const session = await agentPw.connect.startOAuth({
      path: "org_alpha.connections.docs_mcp",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    });
    await agentPw.connect.completeOAuth({
      callbackUri: `https://app.example.com/oauth/callback?code=code-456&state=${session.flowId}`,
    });

    // Now send a 403 insufficient_scope
    const response403 = new Response(null, {
      status: 403,
      headers: {
        "WWW-Authenticate":
          'Bearer error="insufficient_scope", scope="mcp.tools.read mcp.tools.write"',
      },
    });

    const stepUp = await agentPw.connect.prepare({
      path: "org_alpha.connections.docs_mcp",
      resource: "https://docs.example.com/mcp",
      response: response403,
    });

    expect(stepUp.kind).toBe("options");
    if (stepUp.kind !== "options") throw new Error("Expected options");
    expect(stepUp.resolution.reason).toBe("step-up");

    const stepUpOption = stepUp.options[0]!;
    expect(stepUpOption.kind).toBe("oauth");
    if (stepUpOption.kind !== "oauth") throw new Error("Expected oauth");
    // Discovery-backed: source should be "discovery"
    expect(stepUpOption.source).toBe("discovery");
    // Merged scopes: existing "mcp.tools.read" + challenged "mcp.tools.read mcp.tools.write"
    expect(stepUpOption.scopes).toEqual(
      expect.arrayContaining(["mcp.tools.read", "mcp.tools.write"]),
    );
  });

  it("returns null for 403 insufficient_scope with no scope parameter", async () => {
    const { agentPw, completed } = await completeProfileOAuth();

    const response403 = new Response(null, {
      status: 403,
      headers: {
        "WWW-Authenticate": 'Bearer error="insufficient_scope"',
      },
    });

    // Should still return ready since there are no scopes to step up to
    const prepared = await agentPw.connect.prepare({
      path: completed.path,
      resource: "https://api.linear.app/projects",
      response: response403,
    });
    expect(prepared.kind).toBe("ready");
  });
});
