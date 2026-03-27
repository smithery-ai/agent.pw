import { createAgentPw } from "agent.pw";
import { ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  deriveEncryptionKey,
  encryptCredentials,
} from "../packages/server/src/lib/credentials-crypto";
import type { Logger } from "../packages/server/src/lib/logger";
import { createTestDb } from "./setup";
import { must, mustAsync, wrapAgentPw } from "./support/results";

const silentLogger: Logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  child() {
    return this;
  },
};

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
});

describe("createAgentPw edge cases", () => {
  it("validates profile and credential operations and surfaces conflicts", async () => {
    const db = await createTestDb();
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey: Buffer.alloc(32, 7).toString("base64"),
          logger: silentLogger,
          clock: () => new Date("2026-01-01T00:00:00.000Z"),
        }),
      ),
    );

    await expect(agentPw.profiles.get("/")).rejects.toThrow("Invalid profile path '/'");
    await expect(
      agentPw.profiles.put("/shared/github", {
        resourcePatterns: [],
        auth: { kind: "headers", fields: [] },
      }),
    ).rejects.toThrow("Credential Profile resourcePatterns cannot be empty");

    await agentPw.profiles.put("/shared/github", {
      resourcePatterns: ["https://shared.example.com/*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "Token" }],
      },
    });
    await agentPw.profiles.put("/shared/gitlab", {
      resourcePatterns: ["https://shared.example.com/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://auth.example.com/authorize",
        tokenUrl: "https://auth.example.com/token",
        clientId: "shared-client",
      },
    });
    await expect(
      agentPw.profiles.put("/shared/env", {
        resourcePatterns: ["https://env.example.com/*"],
        auth: {
          kind: "env",
          label: "Env vars",
          fields: [
            {
              name: "API_KEY",
              label: "API key",
              description: "Stored as an env secret",
              secret: true,
            },
            {} as never,
          ],
        },
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        path: "/shared/env",
        auth: {
          kind: "env",
          label: "Env vars",
          fields: [
            {
              name: "API_KEY",
              label: "API key",
              description: "Stored as an env secret",
              secret: true,
            },
          ],
        },
      }),
    );
    await expect(
      agentPw.profiles.put("/shared/env_empty", {
        resourcePatterns: ["https://env-empty.example.com/*"],
        auth: {
          kind: "env",
          fields: null as never,
        },
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        path: "/shared/env_empty",
        auth: {
          kind: "env",
          label: undefined,
          fields: [],
        },
      }),
    );

    await expect(
      agentPw.profiles.resolve({
        path: "/shared/connections/tool",
        resource: "https://shared.example.com/api",
      }),
    ).rejects.toThrow(
      "Credential Profile resolves to multiple candidates at the same depth: /shared/github, /shared/gitlab",
    );

    await expect(agentPw.credentials.get("/")).rejects.toThrow("Invalid credential path '/'");
    await expect(agentPw.credentials.list({ path: "/../bad" })).rejects.toThrow(
      "Invalid credential path '/../bad'",
    );
    await expect(agentPw.connect.resolveHeaders({ path: "/missing" })).rejects.toThrow(
      "No credential exists at '/missing'",
    );

    const encrypted = await mustAsync(
      encryptCredentials(Buffer.alloc(32, 7).toString("base64"), {
        headers: { Authorization: "Bearer buffered-token" },
      }),
    );
    const stored = await agentPw.credentials.put({
      path: "/shared/connections/buffered",
      resource: "https://buffered.example.com",
      auth: { kind: "headers", label: "Buffered" },
      secret: encrypted,
    });
    expect(stored.secret.headers).toEqual({
      Authorization: "Bearer buffered-token",
    });
    expect(
      (
        await agentPw.credentials.put({
          path: "/shared/connections/no_resource",
          auth: { kind: "headers", label: "No resource" },
          secret: {
            headers: {
              Authorization: "Bearer no-resource",
            },
          },
        })
      ).auth.resource,
    ).toBeUndefined();

    expect(
      await agentPw.credentials.move(
        "/shared/connections/buffered",
        "/shared/connections/buffered_next",
      ),
    ).toBe(true);
    expect(
      await agentPw.credentials.move(
        "/shared/connections/buffered",
        "/shared/connections/buffered_next",
      ),
    ).toBe(false);
    expect(await agentPw.credentials.delete("/shared/connections/buffered_next")).toBe(true);
    expect(await agentPw.credentials.delete("/shared/connections/buffered_next")).toBe(false);
  });

  it("validates connect helpers and authorization denials", async () => {
    const db = await createTestDb();
    const encryptionKey = await mustAsync(
      deriveEncryptionKey(
        "ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad",
      ),
    );
    const agentPw = wrapAgentPw(
      must(
        await createAgentPw({
          db,
          encryptionKey,
        }),
      ),
    );

    await agentPw.profiles.put("/resend", {
      resourcePatterns: ["https://api.resend.com*"],
      auth: {
        kind: "headers",
        fields: [{ name: "Authorization", label: "API key", prefix: "Bearer " }],
      },
    });
    await agentPw.profiles.put("/linear", {
      resourcePatterns: ["https://api.linear.app/*"],
      auth: {
        kind: "oauth",
        authorizationUrl: "https://accounts.example.com/authorize",
        tokenUrl: "https://accounts.example.com/token",
        clientId: "client-linear",
      },
    });

    const prepared = await agentPw.connect.prepare({
      path: "/org/connections/resend",
      resource: "https://api.resend.com",
    });
    expect(prepared.kind).toBe("options");
    if (prepared.kind !== "options") {
      throw new Error("Expected options");
    }

    await expect(
      agentPw.connect.setHeaders({
        path: "/org/connections/resend",
        resource: "https://api.resend.com",
        headers: { Authorization: 123 as never },
      }),
    ).rejects.toThrow("Invalid header value for 'Authorization'");

    await expect(
      agentPw.connect.setHeaders({
        path: "/org/connections/raw",
        resource: "https://api.resend.com",
        headers: { Authorization: "plain-token" },
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        secret: {
          headers: {
            Authorization: "plain-token",
          },
        },
      }),
    );

    await expect(
      agentPw
        .scope({
          rights: [{ action: "credential.read", root: "/elsewhere" }],
        })
        .credentials.get("/org/connections/resend"),
    ).rejects.toThrow("Missing 'credential.read' for '/org/connections/resend'");

    await agentPw.credentials.put({
      path: "/org/connections/env_only",
      auth: {
        kind: "env",
        label: "Env only",
        resource: "https://env.example.com/api",
      },
      secret: {
        env: {
          API_KEY: "env-secret",
        },
      },
    });

    await expect(
      agentPw.connect.prepare({
        path: "/org/connections/env_only",
        resource: "https://env.example.com/api",
      }),
    ).rejects.toThrow(
      "Credential '/org/connections/env_only' stores env auth and cannot be used with connect.prepare",
    );

    await expect(
      agentPw.connect.resolveHeaders({ path: "/org/connections/env_only" }),
    ).rejects.toThrow("Credential '/org/connections/env_only' stores env auth");

    await expect(
      agentPw.connect.setHeaders({
        path: "/org/connections/env_only",
        headers: { Authorization: "Bearer ignored" },
      }),
    ).rejects.toThrow("Credential '/org/connections/env_only' stores env auth");

    await expect(
      agentPw.connect.setHeaders({
        path: "/org/connections/missing_resource",
        headers: { Authorization: "Bearer missing-resource" },
      }),
    ).rejects.toThrow("connect.setHeaders requires resource when creating a credential");

    await expect(
      agentPw.connect.setHeaders({
        path: "/org/connections/linear",
        resource: "https://api.linear.app/projects",
        headers: { "X-Test": "1" },
      }),
    ).rejects.toThrow(
      "Resource 'https://api.linear.app/projects' requires OAuth; use connect.startOAuth(...)",
    );
  });

  it("falls back to the existing oauth credential when refresh lookup races to null", async () => {
    let reads = 0;
    vi.doMock("../packages/server/src/db/queries.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../packages/server/src/db/queries.js")>();
      const helpers = must(actual.createQueryHelpers());
      return {
        ...actual,
        createQueryHelpers: vi.fn(() =>
          ok({
            ...helpers,
            getCredential: vi.fn(async (_db, path) => {
              if (path !== "/org/connections/docs") {
                return helpers.getCredential(_db, path);
              }
              reads += 1;
              if (reads <= 1) {
                return helpers.getCredential(_db, path);
              }
              return ok(null);
            }),
          }),
        ),
      };
    });

    const { createAgentPw: createMockedAgentPw } = await import("../packages/server/src/index.js");
    const db = await createTestDb();
    const agentPw = wrapAgentPw(
      must(
        await createMockedAgentPw({
          db,
          encryptionKey: Buffer.alloc(32, 7).toString("base64"),
        }),
      ),
    );

    await agentPw.credentials.put({
      path: "/org/connections/docs",
      resource: "https://docs.example.com/mcp",
      auth: { kind: "oauth", label: "Docs" },
      secret: {
        headers: { Authorization: "Bearer docs-token" },
        oauth: {
          accessToken: "docs-token",
        },
      },
    });

    reads = 0;
    await expect(
      agentPw.connect.prepare({
        path: "/org/connections/docs",
        resource: "https://docs.example.com/mcp",
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        kind: "ready",
        credential: expect.objectContaining({
          path: "/org/connections/docs",
          auth: expect.objectContaining({
            kind: "oauth",
            label: "Docs",
          }),
        }),
        headers: {
          Authorization: "Bearer docs-token",
        },
      }),
    );

    reads = 0;
    await expect(
      agentPw.connect.prepare({
        path: "/org/connections/docs",
        resource: "https://docs.example.com/mcp",
      }),
    ).resolves.toEqual(
      expect.objectContaining({
        kind: "ready",
        credential: expect.objectContaining({
          path: "/org/connections/docs",
          auth: expect.objectContaining({
            kind: "oauth",
            label: "Docs",
          }),
        }),
        headers: {
          Authorization: "Bearer docs-token",
        },
        resolution: {
          canonicalResource: "https://docs.example.com/mcp",
          source: null,
          reason: "existing-credential",
          profilePath: null,
          option: null,
        },
      }),
    );
  });

  it("surfaces defensive persistence failures for profiles and credentials", async () => {
    vi.doMock("../packages/server/src/db/queries.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../packages/server/src/db/queries.js")>();
      const helpers = must(actual.createQueryHelpers());
      return {
        ...actual,
        createQueryHelpers: vi.fn(() =>
          ok({
            ...helpers,
            getCredProfile: vi.fn(async () => ok(null)),
            getCredential: vi.fn(async () => ok(null)),
          }),
        ),
      };
    });

    const { createAgentPw: createMockedAgentPw } = await import("../packages/server/src/index.js");
    const db = await createTestDb();
    const agentPw = wrapAgentPw(
      must(
        await createMockedAgentPw({
          db,
          encryptionKey: Buffer.alloc(32, 7).toString("base64"),
        }),
      ),
    );

    await expect(
      agentPw.profiles.put("/linear", {
        resourcePatterns: ["https://api.linear.app/*"],
        auth: {
          kind: "headers",
          fields: [{ name: "Authorization", label: "Token" }],
        },
      }),
    ).rejects.toThrow("Failed to persist Credential Profile '/linear'");

    await expect(
      agentPw.credentials.put({
        path: "/org/connections/linear",
        resource: "https://api.linear.app",
        auth: { kind: "headers" },
        secret: { headers: { Authorization: "Bearer token" } },
      }),
    ).rejects.toThrow("Failed to persist Credential '/org/connections/linear'");
  });
});
