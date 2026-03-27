import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { describe, expect, it } from "vitest";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import { BISCUIT_PRIVATE_KEY, createTestDb } from "./setup";
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
  const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
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

  await agentPw.profiles.put("/linear", {
    resourcePatterns: ["https://api.linear.app/*"],
    auth: {
      kind: "oauth",
      authorizationUrl: "https://accounts.example.com/authorize",
      tokenUrl: "https://accounts.example.com/token",
      revocationUrl: "https://accounts.example.com/revoke",
      clientId: "client-linear",
      clientSecret: "secret-linear",
      clientAuthentication: "client_secret_post",
      scopes: ["read", "write"],
    },
    displayName: "Linear",
  });

  return { agentPw, calls };
}

describe("oauth runtime", () => {
  it("runs profile-backed oauth end to end and refreshes stale credentials", async () => {
    const { agentPw, calls } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "/org_alpha/connections/linear_1",
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
        profilePath: "/linear",
        label: "Linear",
      }),
    );

    const session = await agentPw.connect.start({
      path: "/org_alpha/connections/linear_1",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    });

    expect(session.flowId).toHaveLength(96);
    expect(session.authorizationUrl).toContain("https://accounts.example.com/authorize");
    expect(session.authorizationUrl).toContain("client_id=client-linear");
    expect(session.authorizationUrl).toContain("resource=https%3A%2F%2Fapi.linear.app%2Fprojects");

    const completed = await agentPw.connect.complete({
      callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${session.flowId}`,
    });

    expect(completed.path).toBe("/org_alpha/connections/linear_1");
    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: "/linear",
      label: "Linear",
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
      path: "/org_alpha/connections/docs_mcp",
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

    const session = await agentPw.connect.start({
      path: "/org_alpha/connections/docs_mcp",
      option: oauthOption,
      redirectUri: "https://app.example.com/oauth/callback",
      additionalParameters: { prompt: "consent" },
    });

    expect(session.authorizationUrl).toContain("https://auth.docs.example.com/authorize");
    expect(session.authorizationUrl).toContain(
      "client_id=https%3A%2F%2Fapp.example.com%2F.well-known%2Foauth-client",
    );
    expect(session.authorizationUrl).toContain("prompt=consent");

    const completed = await agentPw.connect.complete({
      callbackUri: `https://app.example.com/oauth/callback?code=code-456&state=${session.flowId}`,
    });

    expect(completed.credential.auth.resource).toBe("https://docs.example.com/mcp");
    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: null,
      label: "Docs MCP via auth.docs.example.com",
      resource: "https://docs.example.com/mcp",
    });

    const handlers = agentPw.connect.createWebHandlers({
      callbackPath: "/oauth/callback",
    });
    const startResponse = await handlers.start(new Request("https://app.example.com/connect"), {
      path: "/org_alpha/connections/docs_mcp_next",
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

    await agentPw.profiles.put("/docs", {
      resourcePatterns: ["https://docs.example.com/mcp"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
        revocationUrl: "https://accounts.example.com/revoke",
        clientId: "client-docs",
        clientSecret: "secret-docs",
        clientAuthentication: "client_secret_post",
        scopes: ["docs.read"],
      },
      displayName: "Docs Profile",
    });

    const prepared = await agentPw.connect.prepare({
      path: "/org_alpha/connections/docs_profiled",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected authorization options");
    }

    expect(prepared.resolution).toEqual({
      canonicalResource: "https://docs.example.com/mcp",
      source: "profile",
      reason: "matched-profile",
      profilePath: "/docs",
      option: {
        kind: "oauth",
        source: "profile",
        resource: "https://docs.example.com/mcp",
        profilePath: "/docs",
        label: "Docs Profile",
        scopes: ["docs.read"],
      },
    });
    const started = await agentPw.connect.start({
      path: "/org_alpha/connections/docs_profiled",
      option: prepared.options[0],
      redirectUri: "https://app.example.com/oauth/callback",
    });

    expect(started.authorizationUrl).toContain("https://accounts.example.com/authorize");

    expect(await agentPw.connect.getFlow(started.flowId)).toEqual({
      flowId: started.flowId,
      path: "/org_alpha/connections/docs_profiled",
      resource: "https://docs.example.com/mcp",
      option: started.option,
      expiresAt: started.expiresAt,
    });

    const completed = await agentPw.connect.complete({
      callbackUri: `https://app.example.com/oauth/callback?code=code-999&state=${started.flowId}`,
    });

    expect(completed.credential.auth).toEqual({
      kind: "oauth",
      profilePath: "/docs",
      label: "Docs Profile",
      resource: "https://docs.example.com/mcp",
    });
    await expect(agentPw.connect.getFlow(started.flowId)).rejects.toThrow(
      `Unknown OAuth flow '${started.flowId}'`,
    );
  });

  it("preserves existing non-auth headers and applies start headers during oauth completion", async () => {
    const { agentPw } = await createOAuthAgent();

    const prepared = await agentPw.connect.prepare({
      path: "/org_alpha/connections/linear_merge",
      resource: "https://api.linear.app/projects",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }
    const option = prepared.options[0];

    await agentPw.credentials.put({
      path: "/org_alpha/connections/linear_merge",
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

    const session = await agentPw.connect.start({
      path: "/org_alpha/connections/linear_merge",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
      headers: {
        Authorization: "Bearer ignored",
        "Proxy-Authorization": "Bearer ignored-proxy",
        "X-Smithery-Connection": "conn_456",
      },
    });

    const completed = await agentPw.connect.complete({
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
      path: "/org_alpha/connections/linear_runtime_headers",
      resource: "https://api.linear.app/projects",
      auth: {
        kind: "oauth",
        profilePath: "/linear",
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

    const merged = await agentPw.connect.putHeaders({
      path: "/org_alpha/connections/linear_runtime_headers",
      headers: {
        Authorization: "Bearer ignored",
        "X-Smithery-Connection": "conn_123",
      },
    });

    expect(merged.auth).toEqual({
      kind: "oauth",
      profilePath: "/linear",
      label: "Linear",
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
});
