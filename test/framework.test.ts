import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { describe, expect, it } from "vitest";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import type { RuleScope } from "../packages/server/src/types";
import { TEST_KEY_MATERIAL, createTestDb } from "./setup";
import { must, mustAsync, wrapAgentPw } from "./support/results";

async function createTestAgent(oauthFetch?: typeof fetch) {
  const db = await createTestDb();
  const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
  return wrapAgentPw(
    must(
      await createAgentPw({
        db,
        encryptionKey,
        oauthFetch,
      }),
    ),
  );
}

function rights(rightsList: RuleScope["rights"]): RuleScope {
  return {
    rights: rightsList,
  };
}

function createDiscoveryFetch() {
  const fetchImpl: typeof fetch = async (input) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    if (url.includes("/.well-known/oauth-protected-resource")) {
      return Response.json({
        resource: "https://docs.example.com/mcp",
        authorization_servers: ["https://accounts.example.com"],
      });
    }

    if (
      url === "https://accounts.example.com/.well-known/oauth-authorization-server" ||
      url === "https://accounts.example.com/.well-known/openid-configuration"
    ) {
      return Response.json({
        issuer: "https://accounts.example.com",
        authorization_endpoint: "https://accounts.example.com/authorize",
        token_endpoint: "https://accounts.example.com/token",
        code_challenge_methods_supported: ["S256"],
      });
    }

    throw new Error(`Unexpected fetch ${url}`);
  };

  return fetchImpl;
}

describe("createAgentPw", () => {
  it("resolves profiles by path and stores exact-path credentials", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("github", {
      resourcePatterns: ["https://api.github.com/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
        clientId: "github-client",
      },
      displayName: "GitHub",
    });
    await agentPw.profiles.put("acme.github", {
      resourcePatterns: ["https://api.github.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Access token", prefix: "Bearer " }],
      },
      displayName: "Acme GitHub",
    });

    expect(
      await agentPw.profiles.resolve({
        path: "acme.connections.github_primary",
        resource: "https://api.github.com/repos/acme/app",
      }),
    ).toEqual(
      expect.objectContaining({
        path: "acme.github",
        displayName: "Acme GitHub",
      }),
    );
    expect((await agentPw.profiles.list({ path: "acme" })).map((profile) => profile.path)).toEqual([
      "acme.github",
    ]);

    const stored = await agentPw.credentials.put({
      path: "acme.connections.github_primary",
      resource: "https://api.github.com",
      auth: {
        kind: "headers",
        profilePath: "acme.github",
        label: "Acme GitHub",
        resource: "https://api.github.com/",
      },
      secret: {
        headers: {
          Authorization: "Bearer github-token",
        },
      },
    });

    expect(stored).toEqual(
      expect.objectContaining({
        path: "acme.connections.github_primary",
        auth: {
          kind: "headers",
          profilePath: "acme.github",
          resource: "https://api.github.com/",
        },
        secret: {
          headers: {
            Authorization: "Bearer github-token",
          },
        },
      }),
    );

    expect(await agentPw.credentials.get("acme.connections.github_primary")).toEqual(
      expect.objectContaining({
        path: "acme.connections.github_primary",
      }),
    );
    expect(
      (await agentPw.credentials.list({ path: "acme.connections" })).map(
        (credential) => credential.path,
      ),
    ).toEqual(["acme.connections.github_primary"]);

    const ready = await agentPw.connect.prepare({
      path: "acme.connections.github_primary",
      resource: "https://api.github.com",
    });
    expect(ready.kind).toBe("ready");
    if (ready.kind === "ready") {
      expect(ready.headers).toEqual({ Authorization: "Bearer github-token" });
    }

    await expect(
      agentPw.connect.prepare({
        path: "acme.connections.github_primary",
        resource: "https://docs.example.com/mcp",
      }),
    ).rejects.toThrow(
      "Credential 'acme.connections.github_primary' is already connected to 'https://api.github.com/', not 'https://docs.example.com/mcp'",
    );
  });

  it("guides header-based connections through prepare metadata and setHeaders", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("resend", {
      resourcePatterns: ["https://api.resend.com*"],
      auth: {
        kind: "headers",
        label: "Resend API key",
        fields: [
          {
            name: "Authorization",
            label: "API key",
            prefix: "Bearer ",
            secret: true,
          },
        ],
      },
      displayName: "Resend",
    });

    const prepared = await agentPw.connect.prepare({
      path: "acme.connections.resend",
      resource: "https://api.resend.com",
    });

    expect(prepared).toEqual({
      kind: "options",
      resolution: {
        canonicalResource: "https://api.resend.com/",
        source: "profile",
        reason: "matched-profile",
        profilePath: "resend",
        option: {
          kind: "headers",
          source: "profile",
          resource: "https://api.resend.com/",
          profilePath: "resend",
          label: "Resend",
          fields: [
            {
              name: "Authorization",
              label: "API key",
              prefix: "Bearer ",
              secret: true,
            },
          ],
        },
      },
      options: [
        {
          kind: "headers",
          source: "profile",
          resource: "https://api.resend.com/",
          profilePath: "resend",
          label: "Resend",
          fields: [
            {
              name: "Authorization",
              label: "API key",
              prefix: "Bearer ",
              secret: true,
            },
          ],
        },
      ],
    });

    if (prepared.kind !== "options") {
      throw new Error("Expected connection options");
    }

    const saved = await agentPw.connect.setHeaders({
      path: "acme.connections.resend",
      resource: "https://api.resend.com",
      headers: {
        Authorization: "Bearer rs_123",
      },
    });

    expect(saved.auth).toEqual({
      kind: "headers",
      profilePath: "resend",
      resource: "https://api.resend.com/",
    });
    expect(saved.secret.headers).toEqual({
      Authorization: "Bearer rs_123",
    });
    expect(await agentPw.connect.resolveHeaders({ path: "acme.connections.resend" })).toEqual({
      Authorization: "Bearer rs_123",
    });
  });

  it("returns config_required for missing literal config fields", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("browserbase", {
      resourcePatterns: ["https://browserbase.run.tools*"],
      config: {
        fields: [
          {
            transport: "header",
            key: "apiKey",
            name: "x-api-key",
            label: "API Key",
            description: "Browserbase API key",
            secret: true,
          },
          {
            transport: "query",
            key: "projectId",
            name: "projectId",
            label: "Project ID",
            description: "Browserbase project",
          },
        ],
      },
      displayName: "Browserbase",
    });

    const prepared = await agentPw.connect.prepare({
      path: "acme.connections.browserbase",
      resource: "https://browserbase.run.tools/mcp",
    });

    expect(prepared).toEqual({
      kind: "config_required",
      config: {
        fields: [
          {
            transport: "header",
            key: "apiKey",
            name: "x-api-key",
            label: "API Key",
            description: "Browserbase API key",
            secret: true,
          },
          {
            transport: "query",
            key: "projectId",
            name: "projectId",
            label: "Project ID",
            description: "Browserbase project",
          },
        ],
        missingKeys: ["apiKey", "projectId"],
      },
      resolution: {
        canonicalResource: "https://browserbase.run.tools/mcp",
        source: "profile",
        reason: "matched-profile",
        profilePath: "browserbase",
        option: null,
      },
    });
  });

  it("keeps pending headers while query config is completed and then offers oauth", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("docs", {
      resourcePatterns: ["https://docs.example.com/*"],
      config: {
        fields: [
          {
            transport: "header",
            key: "apiKey",
            name: "x-api-key",
            label: "API Key",
            secret: true,
          },
          {
            transport: "query",
            key: "workspaceId",
            name: "workspaceId",
            label: "Workspace ID",
          },
        ],
      },
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
        clientId: "docs-client",
      },
      displayName: "Docs",
    });

    const stored = await agentPw.connect.setHeaders({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
      headers: {
        "x-api-key": "secret",
      },
    });

    expect(stored.auth).toEqual({
      kind: "headers",
      profilePath: "docs",
      pending: true,
    });

    const missingQuery = await agentPw.connect.prepare({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
    });

    expect(missingQuery).toEqual({
      kind: "config_required",
      config: {
        fields: [
          {
            transport: "header",
            key: "apiKey",
            name: "x-api-key",
            label: "API Key",
            secret: true,
          },
          {
            transport: "query",
            key: "workspaceId",
            name: "workspaceId",
            label: "Workspace ID",
          },
        ],
        missingKeys: ["workspaceId"],
      },
      resolution: {
        canonicalResource: "https://docs.example.com/mcp",
        source: "profile",
        reason: "matched-profile",
        profilePath: "docs",
        option: {
          kind: "oauth",
          source: "profile",
          resource: "https://docs.example.com/mcp",
          profilePath: "docs",
          label: "Docs",
        },
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp?workspaceId=team-1",
    });

    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }
    expect(prepared.options).toEqual([
      {
        kind: "oauth",
        source: "profile",
        resource: "https://docs.example.com/mcp?workspaceId=team-1",
        profilePath: "docs",
        label: "Docs",
      },
    ]);
  });

  it("prefers matching profiles over discovery and exposes the default option first", async () => {
    let discoveryCalls = 0;
    const agentPw = await createTestAgent(async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

      if (url.includes("/.well-known/oauth-protected-resource")) {
        discoveryCalls += 1;
        return Response.json({
          authorization_servers: ["https://accounts.example.com", "https://backup.example.com"],
          resource: "https://guides.example.com/mcp",
        });
      }

      throw new Error(`Unexpected fetch ${url}`);
    });

    await agentPw.profiles.put("docs", {
      resourcePatterns: ["https://docs.example.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "API key" }],
      },
      displayName: "Docs",
    });

    const profiled = await agentPw.connect.prepare({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
    });

    expect(profiled.kind).toBe("options");
    if (profiled.kind !== "options") {
      throw new Error("Expected connection options");
    }

    expect(profiled.options).toHaveLength(1);
    expect(profiled.options[0]).toEqual(profiled.resolution.option);
    expect(profiled.options[0]).toEqual(
      expect.objectContaining({
        kind: "headers",
        source: "profile",
      }),
    );
    expect(discoveryCalls).toBe(0);

    const discovered = await agentPw.connect.prepare({
      path: "acme.connections.guides",
      resource: "https://guides.example.com/mcp",
    });

    expect(discovered.kind).toBe("options");
    if (discovered.kind !== "options") {
      throw new Error("Expected discovery options");
    }

    expect(discovered.options).toHaveLength(2);
    expect(discovered.options[0]).toEqual(discovered.resolution.option);
    expect(discovered.options).toEqual([
      expect.objectContaining({
        kind: "oauth",
        source: "discovery",
        authorizationServer: "https://accounts.example.com",
      }),
      expect.objectContaining({
        kind: "oauth",
        source: "discovery",
        authorizationServer: "https://backup.example.com",
      }),
    ]);
    expect(discoveryCalls).toBe(1);
  });

  it("creates and overwrites app headers for managed connections", async () => {
    const agentPw = await createTestAgent();

    const created = await agentPw.connect.setHeaders({
      path: "acme.connections.runtime_headers",
      resource: "https://api.resend.com",
      headers: {
        Authorization: "Bearer runtime-1",
        "X-Smithery-Connection": "conn_123",
      },
    });

    expect(created.auth).toEqual({
      kind: "headers",
      profilePath: null,
      resource: "https://api.resend.com/",
    });
    expect(created.secret.headers).toEqual({
      Authorization: "Bearer runtime-1",
      "X-Smithery-Connection": "conn_123",
    });

    const merged = await agentPw.connect.setHeaders({
      path: "acme.connections.runtime_headers",
      headers: {
        Authorization: "Bearer runtime-2",
        "X-Trace-Id": "trace_123",
      },
    });

    expect(merged.secret.headers).toEqual({
      Authorization: "Bearer runtime-2",
      "X-Trace-Id": "trace_123",
    });
  });

  it("uses the caller db for connect.setHeaders", async () => {
    const db = await createTestDb();
    const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey,
        }),
      ),
    );

    await expect(
      db.transaction(async (tx) => {
        await agentPw.profiles.put(
          "resendtx",
          {
            resourcePatterns: ["https://api.resend.com*"],
            auth: {
              kind: "headers",
              fields: [{ name: "Authorization", label: "API key" }],
            },
          },
          { db: tx },
        );

        const saved = await agentPw.connect.setHeaders(
          {
            path: "acme.connections.resend_tx",
            resource: "https://api.resend.com",
            headers: {
              Authorization: "Bearer rs_tx",
            },
          },
          { db: tx },
        );

        expect(saved.auth).toEqual({
          kind: "headers",
          profilePath: "resendtx",
          resource: "https://api.resend.com/",
        });

        throw new Error("rollback setHeaders tx");
      }),
    ).rejects.toThrow("rollback setHeaders tx");

    expect(await agentPw.profiles.get("resendtx")).toBe(null);
    expect(await agentPw.credentials.get("acme.connections.resend_tx")).toBe(null);
  });

  it("returns resolution metadata and ready/unconfigured prepare results", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("resend", {
      resourcePatterns: ["https://api.resend.com*"],
      auth: {
        kind: "headers",
        label: "Resend API key",
        fields: [
          {
            name: "Authorization",
            label: "API key",
            prefix: "Bearer ",
            secret: true,
          },
        ],
      },
      displayName: "Resend",
    });

    expect(
      await agentPw.connect.prepare({
        path: "acme.connections.resend",
        resource: "https://api.resend.com",
      }),
    ).toEqual({
      kind: "options",
      options: [
        {
          kind: "headers",
          source: "profile",
          resource: "https://api.resend.com/",
          profilePath: "resend",
          label: "Resend",
          fields: [
            {
              name: "Authorization",
              label: "API key",
              prefix: "Bearer ",
              secret: true,
            },
          ],
        },
      ],
      resolution: {
        canonicalResource: "https://api.resend.com/",
        source: "profile",
        reason: "matched-profile",
        profilePath: "resend",
        option: {
          kind: "headers",
          source: "profile",
          resource: "https://api.resend.com/",
          profilePath: "resend",
          label: "Resend",
          fields: [
            {
              name: "Authorization",
              label: "API key",
              prefix: "Bearer ",
              secret: true,
            },
          ],
        },
      },
    });

    expect(
      await agentPw.connect.prepare({
        path: "acme.connections.unconfigured",
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

    await agentPw.connect.setHeaders({
      path: "acme.connections.resend",
      resource: "https://api.resend.com",
      headers: {
        Authorization: "Bearer rs_ready",
      },
    });

    await expect(
      agentPw.connect.prepare({
        path: "acme.connections.resend",
        resource: "https://api.resend.com",
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        kind: "ready",
        headers: { Authorization: "Bearer rs_ready" },
        credential: expect.objectContaining({
          path: "acme.connections.resend",
          auth: {
            kind: "headers",
            profilePath: "resend",
            resource: "https://api.resend.com/",
          },
        }),
        resolution: {
          canonicalResource: "https://api.resend.com/",
          source: null,
          reason: "existing-credential",
          profilePath: "resend",
          option: null,
        },
      }),
    );
  });

  it("guides existing oauth connections, discovery-first oauth, and profile oauth without scopes", async () => {
    const db = await createTestDb();
    const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey,
          oauthFetch: createDiscoveryFetch(),
        }),
      ),
    );

    await agentPw.credentials.put({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
      auth: {
        kind: "oauth",
        label: "Docs",
      },
      secret: {
        headers: {
          Authorization: "Bearer docs-token",
        },
        oauth: {
          accessToken: "docs-token",
        },
      },
    });

    const ready = await agentPw.connect.prepare({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
    });
    expect(ready.kind).toBe("ready");
    if (ready.kind === "ready") {
      expect(ready.headers).toEqual({ Authorization: "Bearer docs-token" });
    }

    const discovered = await agentPw.connect.prepare({
      path: "acme.connections.docs_fresh",
      resource: "https://docs.example.com/mcp",
    });
    expect(discovered).toEqual({
      kind: "options",
      resolution: {
        canonicalResource: "https://docs.example.com/mcp",
        source: "discovery",
        reason: "discovered-oauth",
        profilePath: null,
        option: {
          kind: "oauth",
          source: "discovery",
          resource: "https://docs.example.com/mcp",
          authorizationServer: "https://accounts.example.com",
          label: "OAuth via accounts.example.com",
          scopes: [],
        },
      },
      options: [
        {
          kind: "oauth",
          source: "discovery",
          resource: "https://docs.example.com/mcp",
          authorizationServer: "https://accounts.example.com",
          label: "OAuth via accounts.example.com",
          scopes: [],
        },
      ],
    });

    await agentPw.profiles.put("no-scopes", {
      resourcePatterns: ["https://oauth-noscopes.example.com/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://oauth-noscopes.example.com/authorize",
        tokenUrl: "https://oauth-noscopes.example.com/token",
        clientId: "oauth-noscope-client",
      },
    });

    const profiled = await agentPw.connect.prepare({
      path: "acme.connections.no_scopes",
      resource: "https://oauth-noscopes.example.com/api",
    });
    expect(profiled).toEqual({
      kind: "options",
      resolution: {
        canonicalResource: "https://oauth-noscopes.example.com/api",
        source: "profile",
        reason: "matched-profile",
        profilePath: "no-scopes",
        option: {
          kind: "oauth",
          source: "profile",
          resource: "https://oauth-noscopes.example.com/api",
          profilePath: "no-scopes",
          label: "no-scopes",
          scopes: undefined,
        },
      },
      options: [
        {
          kind: "oauth",
          source: "profile",
          resource: "https://oauth-noscopes.example.com/api",
          profilePath: "no-scopes",
          label: "no-scopes",
          scopes: undefined,
        },
      ],
    });
  });

  it("supports scoped APIs over connect, credentials, and profiles", async () => {
    const agentPw = await createTestAgent();

    await agentPw.profiles.put("profiles.resend", {
      resourcePatterns: ["https://api.resend.com*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "API key", prefix: "Bearer " }],
      },
    });
    await agentPw.credentials.put({
      path: "acme.connections.resend",
      resource: "https://api.resend.com",
      auth: { kind: "headers", profilePath: "profiles.resend" },
      secret: { headers: { Authorization: "Bearer resend-token" } },
    });
    await agentPw.credentials.put({
      path: "beta.connections.docs",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "headers" },
      secret: { headers: { Authorization: "Bearer docs-token" } },
    });

    const api = agentPw.scope(
      rights([
        { action: "credential.use", root: "acme" },
        { action: "credential.read", root: "acme" },
        { action: "credential.manage", root: "acme" },
        { action: "credential.connect", root: "acme" },
        { action: "profile.read", root: "profiles" },
        { action: "profile.manage", root: "profiles" },
      ]),
    );

    const allowed = {
      headers: await api.connect.resolveHeaders({ path: "acme.connections.resend" }),
      credentials: await api.credentials.list({ path: "acme.connections" }),
      profiles: await api.profiles.list({ path: "profiles" }),
    };

    expect(allowed.headers).toEqual({ Authorization: "Bearer resend-token" });
    expect(allowed.credentials.map((credential) => credential.path)).toEqual([
      "acme.connections.resend",
    ]);
    expect(allowed.profiles.map((profile) => profile.path)).toEqual(["profiles.resend"]);

    const socket = agentPw.scope(rights([{ action: "credential.use", root: "acme" }]));
    await expect(
      socket.connect.resolveHeaders({ path: "acme.connections.resend" }),
    ).resolves.toEqual({
      Authorization: "Bearer resend-token",
    });

    await expect(
      agentPw.scope(rights([{ action: "credential.connect", root: "acme" }])).connect.prepare({
        path: "acme.connections.resend",
        resource: "https://api.resend.com",
      }),
    ).rejects.toThrow("Missing 'credential.use' for 'acme.connections.resend'");
  });

  it("does not leak oauth flow secrets through scoped getFlow", async () => {
    const db = await createTestDb();
    const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey,
          flowStore: createInMemoryFlowStore(),
          oauthFetch: createDiscoveryFetch(),
          oauthClient: {
            clientId: "docs-client",
          },
        }),
      ),
    );

    const scoped = agentPw.scope(rights([{ action: "credential.connect", root: "acme" }]));
    const prepared = await scoped.connect.prepare({
      path: "acme.connections.docs_fresh",
      resource: "https://docs.example.com/mcp",
    });
    if (prepared.kind !== "options") {
      throw new Error("Expected oauth options");
    }

    const option = prepared.options[0];
    if (!option || option.kind !== "oauth") {
      throw new Error("Expected oauth option");
    }

    const session = await scoped.connect.startOAuth({
      path: "acme.connections.docs_fresh",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    });

    expect(await scoped.connect.getFlow(session.flowId)).toEqual({
      flowId: session.flowId,
      path: "acme.connections.docs_fresh",
      resource: "https://docs.example.com/mcp",
      expiresAt: session.expiresAt,
    });
  });
});
