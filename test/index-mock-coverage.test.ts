import { err, ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inputError } from "../packages/server/src/errors";
import { errorOf, must } from "./support/results";

const DATE = new Date("2026-01-01T00:00:00.000Z");

function profileRow(path: string, auth: Record<string, unknown>) {
  return {
    path,
    resourcePatterns: ["https://profile.example.com/*"],
    auth,
    displayName: null,
    description: null,
    createdAt: DATE,
    updatedAt: DATE,
  };
}

function credentialRow(path: string, auth: Record<string, unknown>, secret = "header-secret") {
  return {
    path,
    auth,
    secret: Buffer.from(secret),
    createdAt: DATE,
    updatedAt: DATE,
  };
}

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  vi.doUnmock("../packages/server/src/db/queries.js");
  vi.doUnmock("../packages/server/src/paths.js");
  vi.doUnmock("../packages/server/src/oauth.js");
  vi.doUnmock("../packages/server/src/rules.js");
  vi.doUnmock("../packages/server/src/lib/credentials-crypto.js");
});

describe("index mock coverage", () => {
  it("surfaces query helper initialization failures", async () => {
    vi.doMock("../packages/server/src/db/queries.js", () => ({
      createQueryHelpers: () => err(inputError("mock query init failure")),
    }));

    const { createAgentPw } = await import("../packages/server/src/index");
    expect(errorOf(await createAgentPw({ db: {} as never, encryptionKey: "test" })).message).toBe(
      "mock query init failure",
    );
  });

  it("covers dead path guards across the public and scoped APIs", async () => {
    vi.doMock("../packages/server/src/paths.js", async () => {
      const actual = await vi.importActual<typeof import("../packages/server/src/paths")>(
        "../packages/server/src/paths.js",
      );
      return {
        ...actual,
        assertPath(path: string, label: string) {
          return path.startsWith("bad") ? err(inputError(`mock ${label}`)) : ok(path);
        },
        assertOptionalPath(path: string | undefined, label: string) {
          return path?.startsWith("bad") ? err(inputError(`mock ${label}`)) : ok(path);
        },
      };
    });

    const { createAgentPw } = await import("../packages/server/src/index");
    const agentPw = must(
      await createAgentPw({
        db: {} as never,
        encryptionKey: "test",
      }),
    );
    const scoped = agentPw.scope({ rights: [] });
    const option = {
      kind: "oauth" as const,
      source: "discovery" as const,
      label: "OAuth",
      resource: "https://resource.example.com",
      authorizationServer: "https://issuer.example.com",
    };

    expect(
      errorOf(await agentPw.profiles.resolve({ path: "bad.path", resource: "https://ok" })).message,
    ).toBe("mock path");
    expect(errorOf(await agentPw.profiles.get("bad.profile")).message).toBe("mock profile path");
    expect(errorOf(await agentPw.profiles.list({ path: "bad.profile" })).message).toBe(
      "mock profile path",
    );
    expect(
      errorOf(
        await agentPw.profiles.put("bad.profile", {
          resourcePatterns: ["https://ok/*"],
          auth: { kind: "headers", fields: [] },
        }),
      ).message,
    ).toBe("mock profile path");
    expect(errorOf(await agentPw.profiles.delete("bad.profile")).message).toBe("mock profile path");

    expect(errorOf(await agentPw.credentials.get("bad.credential")).message).toBe(
      "mock credential path",
    );
    expect(errorOf(await agentPw.credentials.list({ path: "bad.credential" })).message).toBe(
      "mock credential path",
    );
    expect(
      errorOf(
        await agentPw.credentials.put({
          path: "bad.credential",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("mock credential path");
    expect(errorOf(await agentPw.credentials.move("bad.source", "good.target")).message).toBe(
      "mock source path",
    );
    expect(errorOf(await agentPw.credentials.move("good.source", "bad.target")).message).toBe(
      "mock target path",
    );
    expect(errorOf(await agentPw.credentials.delete("bad.credential")).message).toBe(
      "mock credential path",
    );

    expect(
      errorOf(await agentPw.connect.prepare({ path: "bad.path", resource: "https://ok" })).message,
    ).toBe("mock path");
    expect(
      errorOf(
        await agentPw.connect.startOAuth({
          path: "bad.path",
          option,
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock path");
    expect(
      errorOf(await agentPw.connect.setHeaders({ path: "bad.path", headers: {} })).message,
    ).toBe("mock path");
    expect(errorOf(await agentPw.connect.resolveHeaders({ path: "bad.path" })).message).toBe(
      "mock path",
    );
    expect(errorOf(await agentPw.connect.disconnect({ path: "bad.path" })).message).toBe(
      "mock path",
    );

    expect(
      errorOf(await scoped.connect.prepare({ path: "bad.path", resource: "https://ok" })).message,
    ).toBe("mock path");
    expect(
      errorOf(
        await scoped.connect.startOAuth({
          path: "bad.path",
          option,
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock path");
    expect(
      errorOf(await scoped.connect.setHeaders({ path: "bad.path", headers: {} })).message,
    ).toBe("mock path");
    expect(errorOf(await scoped.connect.resolveHeaders({ path: "bad.path" })).message).toBe(
      "mock path",
    );
    expect(errorOf(await scoped.connect.disconnect({ path: "bad.path" })).message).toBe(
      "mock path",
    );

    expect(errorOf(await scoped.credentials.get("bad.credential")).message).toBe(
      "mock credential path",
    );
    expect(errorOf(await scoped.credentials.list({ path: "bad.credential" })).message).toBe(
      "mock credential path",
    );
    expect(
      errorOf(
        await scoped.credentials.put({
          path: "bad.credential",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("mock credential path");
    expect(errorOf(await scoped.credentials.move("bad.source", "good.target")).message).toBe(
      "mock source path",
    );
    expect(errorOf(await scoped.credentials.move("good.source", "bad.target")).message).toBe(
      "mock target path",
    );
    expect(errorOf(await scoped.credentials.delete("bad.credential")).message).toBe(
      "mock credential path",
    );

    expect(errorOf(await scoped.profiles.get("bad.profile")).message).toBe("mock profile path");
    expect(errorOf(await scoped.profiles.list({ path: "bad.profile" })).message).toBe(
      "mock profile path",
    );
    expect(
      errorOf(
        await scoped.profiles.put("bad.profile", {
          resourcePatterns: ["https://ok/*"],
          auth: { kind: "headers", fields: [] },
        }),
      ).message,
    ).toBe("mock profile path");
    expect(errorOf(await scoped.profiles.delete("bad.profile")).message).toBe("mock profile path");
  });

  it("covers wrapper propagation, unconfigured resolution, and scoped denials", async () => {
    vi.doMock("../packages/server/src/db/queries.js", () => ({
      createQueryHelpers: () =>
        ok({
          async getMatchingCredProfiles(_db: unknown, path: string) {
            if (path === "profile.err" || path === "setheaders.profile.err") {
              return err(inputError("mock match failure"));
            }
            return ok([]);
          },
          async getCredProfile(_db: unknown, path: string) {
            return path === "profile.get.err"
              ? err(inputError("mock profile get failure"))
              : ok(null);
          },
          async listCredProfiles(_db: unknown, options?: { path?: string }) {
            if (options?.path === "profile.list.err") {
              return err(inputError("mock profile list failure"));
            }
            if (options?.path === "profile.bad.row") {
              return ok([profileRow("profile.bad.row", "bad" as never)]);
            }
            return ok([]);
          },
          async upsertCredProfile(_db: unknown, path: string) {
            return path === "profile.put.err"
              ? err(inputError("mock profile put failure"))
              : ok(profileRow(path, { kind: "headers", fields: [] }));
          },
          async deleteCredProfile(_db: unknown, path: string) {
            return path === "profile.delete.err"
              ? err(inputError("mock profile delete failure"))
              : ok(true);
          },
          async getCredential(_db: unknown, path: string) {
            if (path === "credential.query.err" || path === "setheaders.query.err") {
              return err(inputError("mock credential get failure"));
            }
            if (path === "oauth.refresh.err") {
              return ok(
                credentialRow("oauth.refresh.err", {
                  kind: "oauth",
                  resource: "https://resource.example.com",
                }),
              );
            }
            if (path === "oauth.refresh.fallback") {
              return ok(
                credentialRow(
                  "oauth.refresh.fallback",
                  {
                    kind: "oauth",
                    resource: "https://resource.example.com",
                  },
                  "oauth-secret",
                ),
              );
            }
            if (path === "oauth.secret.missing") {
              return ok(
                credentialRow(
                  "oauth.secret.missing",
                  {
                    kind: "oauth",
                    resource: "https://resource.example.com",
                  },
                  "oauth-missing",
                ),
              );
            }
            if (path === "oauth.profile.persist") {
              return ok(
                credentialRow(
                  "oauth.profile.persist",
                  {
                    kind: "oauth",
                    profilePath: "profiles.oauth",
                    resource: "https://resource.example.com",
                  },
                  "oauth-secret",
                ),
              );
            }
            if (path === "oauth.nullish.persist") {
              return ok(
                credentialRow(
                  "oauth.nullish.persist",
                  {
                    kind: "oauth",
                  },
                  "oauth-secret",
                ),
              );
            }
            if (path === "headers.secret.missing" || path === "headerless.prepare") {
              return ok(
                credentialRow(
                  path,
                  {
                    kind: "headers",
                    resource: "https://resource.example.com",
                  },
                  "headers-missing",
                ),
              );
            }
            if (path === "headers.profile.persist") {
              return ok(
                credentialRow("headers.profile.persist", {
                  kind: "headers",
                  profilePath: "profiles.headers",
                  resource: "https://resource.example.com",
                }),
              );
            }
            if (path === "headers.nullish.persist") {
              return ok(
                credentialRow("headers.nullish.persist", {
                  kind: "headers",
                }),
              );
            }
            if (path === "decrypt.fail") {
              return ok(
                credentialRow(
                  "decrypt.fail",
                  {
                    kind: "headers",
                    resource: "https://resource.example.com",
                  },
                  "decrypt-fail",
                ),
              );
            }
            return ok(null);
          },
          async listCredentials(_db: unknown, options?: { path?: string }) {
            if (options?.path === "credential.list.err") {
              return err(inputError("mock credential list failure"));
            }
            if (options?.path === "credential.bad.row") {
              return ok([credentialRow("credential.bad.row", "bad" as never)]);
            }
            return ok([]);
          },
          async upsertCredential(
            _db: unknown,
            input: { path: string; auth: Record<string, unknown>; secret: Buffer },
          ) {
            if (input.path === "credential.put.err") {
              return err(inputError("mock credential put failure"));
            }
            return ok(credentialRow(input.path, input.auth, input.secret.toString()));
          },
          async moveCredential(_db: unknown, fromPath: string, toPath: string) {
            return fromPath === "move.err" || toPath === "move.err"
              ? err(inputError("mock move failure"))
              : ok(true);
          },
          async deleteCredential(_db: unknown, path: string) {
            return path === "delete.err"
              ? err(inputError("mock credential delete failure"))
              : ok(true);
          },
        }),
    }));
    vi.doMock("../packages/server/src/lib/credentials-crypto.js", async () => {
      const actual = await vi.importActual<
        typeof import("../packages/server/src/lib/credentials-crypto")
      >("../packages/server/src/lib/credentials-crypto.js");
      return {
        ...actual,
        async decryptCredentials(_key: string, encrypted: Buffer) {
          switch (encrypted.toString()) {
            case "decrypt-fail":
              return err(inputError("mock decrypt failure"));
            case "oauth-missing":
              return ok({});
            case "oauth-secret":
              return ok({
                headers: { Authorization: "Bearer oauth" },
                oauth: {
                  accessToken: "oauth-token",
                  clientId: "client-id",
                  clientAuthentication: "none",
                },
              });
            case "headers-missing":
              return ok({});
            default:
              return ok({ headers: { Authorization: "Bearer ok" } });
          }
        },
        async encryptCredentials(_key: string, secret: Record<string, unknown>) {
          return "encryptFail" in secret
            ? err(inputError("mock encrypt failure"))
            : ok(Buffer.from("stored-secret"));
        },
      };
    });
    vi.doMock("../packages/server/src/oauth.js", () => ({
      createOAuthService: () => ({
        async discoverResource() {
          return err(inputError("mock discovery failure"));
        },
        async getFlow(id: string) {
          return id === "flow.denied"
            ? ok({
                id,
                path: "org.denied",
                credential: {},
                redirectUri: "https://app.example.com/oauth/callback",
                codeVerifier: "verifier",
                expiresAt: DATE,
                oauthConfig: {
                  clientId: "client-id",
                  clientAuthentication: "none",
                  resource: "https://resource.example.com",
                },
              })
            : err(inputError("mock flow failure"));
        },
        async refreshCredential(path: string) {
          if (path === "oauth.refresh.err") {
            return err(inputError("mock refresh failure"));
          }
          if (path === "headerless.prepare") {
            return ok({
              path,
              auth: { kind: "headers", resource: "https://resource.example.com" },
              secret: {},
              createdAt: DATE,
              updatedAt: DATE,
            });
          }
          if (path === "resolve.err") {
            return err(inputError("mock resolve failure"));
          }
          if (path === "resolve.missing") {
            return ok(null);
          }
          return ok(null);
        },
        async startAuthorization() {
          return err(inputError("mock start failure"));
        },
        async completeAuthorization() {
          return err(inputError("mock completion failure"));
        },
        async parseScopeChallenge() {
          return ok(null);
        },
        async disconnect() {
          return err(inputError("mock disconnect failure"));
        },
        createWebHandlers() {
          return {
            async start() {
              return new Response("ok");
            },
            async callback() {
              return new Response("ok");
            },
          };
        },
        createClientMetadataDocument() {
          return ok({ client_id: "https://client.example.com" });
        },
        createClientMetadataResponse() {
          return err(inputError("mock metadata failure"));
        },
      }),
    }));
    vi.doMock("../packages/server/src/rules.js", async () => {
      const actual = await vi.importActual<typeof import("../packages/server/src/rules")>(
        "../packages/server/src/rules.js",
      );
      return {
        ...actual,
        authorizeRules({ path }: { path: string }) {
          return path.includes("denied")
            ? { authorized: false, error: "mock rule denial" }
            : { authorized: true };
        },
        can({ path }: { path: string }) {
          return !path.includes("filtered");
        },
      };
    });

    const { createAgentPw } = await import("../packages/server/src/index");
    const agentPw = must(
      await createAgentPw({
        db: {} as never,
        encryptionKey: "test",
      }),
    );
    const scoped = agentPw.scope({ rights: [{ action: "credential.manage", root: "org" }] });
    const oauthOption = {
      kind: "oauth" as const,
      source: "discovery" as const,
      label: "OAuth",
      resource: "https://resource.example.com",
      authorizationServer: "https://issuer.example.com",
    };

    expect(
      errorOf(await agentPw.profiles.resolve({ path: "profile.err", resource: "https://ok" }))
        .message,
    ).toBe("mock match failure");
    expect(
      errorOf(await agentPw.profiles.resolve({ path: "org.oauth", resource: "not-a-url" })).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(errorOf(await agentPw.profiles.get("profile.get.err")).message).toBe(
      "mock profile get failure",
    );
    expect(await agentPw.profiles.get("profile.get.ok", { db: {} as never })).toEqual({
      ok: true,
      value: null,
    });
    expect(errorOf(await agentPw.profiles.list({ path: "profile.bad.row" })).message).toBe(
      "Invalid profile auth payload",
    );
    expect(
      errorOf(
        await agentPw.profiles.put("profile.put.err", {
          resourcePatterns: ["https://ok/*"],
          auth: { kind: "headers", fields: [] },
        }),
      ).message,
    ).toBe("mock profile put failure");
    expect(errorOf(await agentPw.profiles.delete("profile.delete.err")).message).toBe(
      "mock profile delete failure",
    );
    expect(
      await agentPw.profiles.delete("profile.delete.ok", { db: {} as never, recursive: true }),
    ).toEqual({
      ok: true,
      value: true,
    });

    expect(errorOf(await agentPw.credentials.get("credential.query.err")).message).toBe(
      "mock credential get failure",
    );
    expect(errorOf(await agentPw.credentials.get("decrypt.fail")).message).toBe(
      "mock decrypt failure",
    );
    expect(errorOf(await agentPw.credentials.list({ path: "credential.bad.row" })).message).toBe(
      "Invalid credential auth payload",
    );
    expect(
      errorOf(
        await agentPw.credentials.put({
          path: "credential.invalid.resource",
          auth: { kind: "headers", resource: "not-a-url" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(
        await agentPw.credentials.put({
          path: "credential.invalid.top.resource",
          resource: "not-a-url",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(
        await agentPw.credentials.put({
          path: "credential.encrypt.err",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" }, encryptFail: true } as never,
        }),
      ).message,
    ).toBe("mock encrypt failure");
    expect(
      errorOf(
        await agentPw.credentials.put({
          path: "credential.put.err",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("mock credential put failure");
    expect(errorOf(await agentPw.credentials.move("move.err", "next")).message).toBe(
      "mock move failure",
    );
    expect(errorOf(await agentPw.credentials.delete("delete.err")).message).toBe(
      "mock credential delete failure",
    );
    expect(await agentPw.credentials.move("move.ok", "move.next", { db: {} as never })).toEqual({
      ok: true,
      value: true,
    });
    expect(
      await agentPw.credentials.delete("delete.ok", { db: {} as never, recursive: true }),
    ).toEqual({ ok: true, value: true });

    expect(
      errorOf(await agentPw.connect.prepare({ path: "org.oauth", resource: "not-a-url" })).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(
        await agentPw.connect.prepare({
          path: "credential.query.err",
          resource: "https://resource.example.com",
        }),
      ).message,
    ).toBe("mock credential get failure");
    expect(
      errorOf(
        await agentPw.connect.prepare({
          path: "profile.err",
          resource: "https://resource.example.com",
        }),
      ).message,
    ).toBe("mock match failure");
    expect(
      (await agentPw.connect.prepare({ path: "plain.unconfigured", resource: "https://ok" })).ok,
    ).toBe(true);
    expect(
      await agentPw.connect.prepare({
        path: "oauth.refresh.fallback",
        resource: "https://resource.example.com",
      }),
    ).toEqual({
      ok: true,
      value: expect.objectContaining({
        kind: "ready",
        credential: expect.objectContaining({ path: "oauth.refresh.fallback" }),
      }),
    });
    expect(
      errorOf(
        await agentPw.connect.prepare({
          path: "oauth.refresh.err",
          resource: "https://resource.example.com",
        }),
      ).message,
    ).toBe("mock refresh failure");
    expect(
      errorOf(
        await agentPw.connect.prepare({
          path: "headerless.prepare",
          resource: "https://resource.example.com",
        }),
      ).message,
    ).toBe("Credential 'headerless.prepare' does not have header-based auth");
    expect(
      errorOf(
        await agentPw.connect.startOAuth({
          path: "good.path",
          option: oauthOption,
          redirectUri: "https://app.example.com/oauth/callback",
          headers: null as never,
        }),
      ).message,
    ).toBe("Expected headers object");
    expect(
      errorOf(
        await agentPw.connect.setHeaders({
          path: "setheaders.query.err",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("mock credential get failure");
    expect(
      errorOf(
        await agentPw.connect.setHeaders({
          path: "new.invalid.resource",
          resource: "not-a-url",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");
    expect(
      errorOf(
        await agentPw.connect.setHeaders({
          path: "setheaders.profile.err",
          resource: "https://ok",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("mock match failure");
    expect(
      errorOf(
        await agentPw.connect.setHeaders({
          path: "oauth.secret.missing",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("Credential 'oauth.secret.missing' does not have oauth auth");
    expect(
      (
        await agentPw.connect.setHeaders({
          path: "oauth.profile.persist",
          headers: { "X-Test": "1" },
        })
      ).ok,
    ).toBe(true);
    expect(
      (
        await agentPw.connect.setHeaders({
          path: "oauth.nullish.persist",
          headers: { "X-Test": "1" },
        })
      ).ok,
    ).toBe(true);
    expect(
      errorOf(
        await agentPw.connect.setHeaders({
          path: "headers.secret.missing",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("Credential 'headers.secret.missing' does not have header-based auth");
    expect(
      (
        await agentPw.connect.setHeaders({
          path: "headers.profile.persist",
          headers: { "X-Test": "1" },
        })
      ).ok,
    ).toBe(true);
    expect(
      (
        await agentPw.connect.setHeaders({
          path: "headers.nullish.persist",
          headers: { "X-Test": "1" },
        })
      ).ok,
    ).toBe(true);
    expect(errorOf(await agentPw.connect.resolveHeaders({ path: "resolve.err" })).message).toBe(
      "mock resolve failure",
    );
    expect(errorOf(await agentPw.connect.resolveHeaders({ path: "resolve.missing" })).message).toBe(
      "No credential exists at 'resolve.missing'",
    );
    expect(
      errorOf(
        agentPw.connect.createClientMetadataResponse({
          clientId: "https://client.example.com",
          redirectUris: ["https://app.example.com/oauth/callback"],
        }),
      ).message,
    ).toBe("mock metadata failure");

    expect(
      errorOf(await scoped.connect.prepare({ path: "org.denied", resource: "https://ok" })).message,
    ).toBe("mock rule denial");
    expect(
      errorOf(
        await scoped.connect.prepare({
          path: "profile.err",
          resource: "https://resource.example.com",
        }),
      ).message,
    ).toBe("mock match failure");
    expect(errorOf(await scoped.connect.getFlow("flow.denied")).message).toBe("mock rule denial");
    expect(
      errorOf(
        await scoped.connect.startOAuth({
          path: "org.denied",
          option: oauthOption,
          redirectUri: "https://app.example.com/oauth/callback",
        }),
      ).message,
    ).toBe("mock rule denial");
    expect(
      errorOf(
        await scoped.connect.completeOAuth({
          callbackUri: "https://app.example.com/oauth/callback?state=flow.denied",
        }),
      ).message,
    ).toBe("mock rule denial");
    expect(
      errorOf(
        await scoped.connect.setHeaders({
          path: "org.denied",
          headers: { Authorization: "Bearer token" },
        }),
      ).message,
    ).toBe("mock rule denial");
    expect(errorOf(await scoped.connect.resolveHeaders({ path: "org.denied" })).message).toBe(
      "mock rule denial",
    );
    expect(errorOf(await scoped.connect.disconnect({ path: "org.denied" })).message).toBe(
      "mock rule denial",
    );

    expect(errorOf(await scoped.credentials.get("org.denied")).message).toBe("mock rule denial");
    expect(errorOf(await scoped.credentials.list({ path: "credential.list.err" })).message).toBe(
      "mock credential list failure",
    );
    expect(
      errorOf(
        await scoped.credentials.put({
          path: "org.denied",
          auth: { kind: "headers" },
          secret: { headers: { Authorization: "Bearer token" } },
        }),
      ).message,
    ).toBe("mock rule denial");
    expect(errorOf(await scoped.credentials.move("org.denied", "org.allowed.next")).message).toBe(
      "mock rule denial",
    );
    expect(errorOf(await scoped.credentials.move("org.allowed", "org.denied.next")).message).toBe(
      "mock rule denial",
    );
    expect(errorOf(await scoped.credentials.delete("org.denied")).message).toBe("mock rule denial");

    expect(errorOf(await scoped.profiles.get("org.denied")).message).toBe("mock rule denial");
    expect(errorOf(await scoped.profiles.list({ path: "profile.list.err" })).message).toBe(
      "mock profile list failure",
    );
    expect(
      errorOf(
        await scoped.profiles.put("org.denied", {
          resourcePatterns: ["https://ok/*"],
          auth: { kind: "headers", fields: [] },
        }),
      ).message,
    ).toBe("mock rule denial");
    expect(errorOf(await scoped.profiles.delete("org.denied")).message).toBe("mock rule denial");
  });
});
