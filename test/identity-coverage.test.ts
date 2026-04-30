import { createAgentPw } from "agent.pw";
import { err, ok } from "okay-error";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createIdentityGrantService } from "../packages/server/src/identity";
import { inputError } from "../packages/server/src/errors";
import type {
  ConnectClassifyResponseResult,
  IdentityGrantOptions,
} from "../packages/server/src/types";
import { deriveEncryptionKey } from "../packages/server/src/lib/credentials-crypto";
import { TEST_KEY_MATERIAL, createTestDb } from "./setup";
import { errorOf, must, mustAsync } from "./support/results";

const NOW = new Date("2026-04-29T12:00:00.000Z");
const CHALLENGE = {
  status: 401,
  headers: {
    "www-authenticate": 'Bearer scope="mcp.read"',
  },
};
const CLASSIFIED = {
  kind: "auth-required",
  scheme: "bearer",
  scopes: ["mcp.read"],
} satisfies ConnectClassifyResponseResult;

async function createSigningKey() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  return {
    ...privateJwk,
    kty: "RSA" as const,
    n: privateJwk.n!,
    e: privateJwk.e!,
    d: privateJwk.d!,
    kid: "identity-key-1",
  };
}

function textJsonResponse(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function bearerChallenge(resourceMetadataUrl?: string) {
  return {
    status: 401,
    headers: {
      "www-authenticate": resourceMetadataUrl
        ? `Bearer resource_metadata="${resourceMetadataUrl}", scope="mcp.read"`
        : 'Bearer scope="mcp.read"',
    },
  };
}

function createIdentityFetch(
  overrides: Record<string, Response | Error> = {},
  tokenBody: Record<string, unknown> = {
    access_token: "downstream-access",
    token_type: "Bearer",
  },
): typeof fetch {
  return async (input) => {
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
      url === "https://rs.example.com/.well-known/oauth-protected-resource/mcp" ||
      url === "https://rs.example.com/.well-known/oauth-protected-resource"
    ) {
      return Response.json({
        resource: "https://rs.example.com/mcp",
        authorization_servers: ["https://as.example.com"],
      });
    }

    if (url === "https://as.example.com/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: "https://as.example.com",
        token_endpoint: "https://as.example.com/token",
        grant_types_supported: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
        authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
        token_endpoint_auth_signing_alg_values_supported: ["RS256"],
      });
    }

    if (url === "https://as.example.com/token") {
      return Response.json(tokenBody);
    }

    throw new Error(`Unexpected fetch ${url}`);
  };
}

async function createGrant(
  input: Partial<IdentityGrantOptions<string>> & { omitKid?: boolean } = {},
): Promise<IdentityGrantOptions<string>> {
  const privateJwk = await createSigningKey();
  if (input.omitKid) {
    delete privateJwk.kid;
  }
  return {
    issuer: "https://issuer.example.com",
    clientId: "identity-client",
    signingKey: {
      privateJwk,
    },
    subject: ({ principal }) => `subject:${principal}`,
    ...input,
  };
}

async function createService(input: {
  grant?: IdentityGrantOptions<string>;
  fetchImpl?: typeof fetch;
  defaultClientId?: string;
  classification?: ConnectClassifyResponseResult;
}) {
  return createIdentityGrantService({
    identityGrant: input.grant,
    customFetch: input.fetchImpl ?? createIdentityFetch(),
    clock: () => NOW,
    defaultClientId: input.defaultClientId,
    classifyResponse: async () => ok(input.classification ?? CLASSIFIED),
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("identity branch coverage", () => {
  it("covers disabled, invalid input, no challenge, classifier error, and JWKS response errors", async () => {
    const disabled = await createService({});

    expect(disabled.createIdentityJwksResponse().ok).toBe(false);
    expect(
      must(
        await disabled.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          principal: "user_1",
        }),
      ),
    ).toEqual({ kind: "not_applicable", reason: "identity-grant-disabled" });

    const grant = await createGrant();
    const service = await createService({ grant });
    expect(
      errorOf(
        await service.exchangeIdentityGrant({
          resource: "not-a-url",
          response: CHALLENGE,
          principal: "user_1",
        }),
      ).message,
    ).toBe("Invalid resource 'not-a-url'");

    const noChallenge = await createService({
      grant,
      classification: { kind: "none" },
    });
    expect(
      must(
        await noChallenge.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          principal: "user_1",
        }),
      ),
    ).toEqual({ kind: "not_applicable", reason: "not-auth-challenge" });

    const classifierError = createIdentityGrantService({
      identityGrant: grant,
      clock: () => NOW,
      classifyResponse: async () => err(inputError("mock classify failure")),
    });
    expect(
      errorOf(
        await classifierError.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          principal: "user_1",
        }),
      ).message,
    ).toBe("mock classify failure");
  });

  it("covers metadata discovery and authorization server non-support reasons", async () => {
    const grant = await createGrant();

    const metadataFetchError = await createService({
      grant,
      fetchImpl: createIdentityFetch({
        "https://rs.example.com/.well-known/oauth-protected-resource/mcp": new Error("offline"),
      }),
    });
    expect(
      errorOf(
        await metadataFetchError.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_metadata_not_found");

    const invalidMetadata = await createService({
      grant,
      fetchImpl: createIdentityFetch({
        "https://rs.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
          resource: "https://other.example.com/mcp",
          authorization_servers: ["https://as.example.com"],
        }),
      }),
    });
    expect(
      must(
        await invalidMetadata.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ),
    ).toEqual({ kind: "unsupported", reason: "metadata-not-found" });

    const noAuthorizationServer = await createService({
      grant,
      fetchImpl: createIdentityFetch({
        "https://rs.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
          resource: "https://rs.example.com/mcp",
        }),
      }),
    });
    expect(
      must(
        await noAuthorizationServer.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ),
    ).toEqual({ kind: "unsupported", reason: "authorization-server-not-found" });

    const invalidAuthorizationServer = await createService({
      grant,
      fetchImpl: createIdentityFetch({
        "https://rs.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
          resource: "https://rs.example.com/mcp",
          authorization_servers: ["not-a-url"],
        }),
      }),
    });
    expect(
      errorOf(
        await invalidAuthorizationServer.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_metadata_not_found");

    for (const [body, reason] of [
      [{ issuer: "https://as.example.com" }, "authorization-server-not-found"],
      [
        {
          issuer: "https://as.example.com",
          token_endpoint: "https://as.example.com/token",
          grant_types_supported: [],
        },
        "unsupported-grant-type",
      ],
      [
        {
          issuer: "https://as.example.com",
          token_endpoint: "https://as.example.com/token",
          grant_types_supported: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
          authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
          token_endpoint_auth_methods_supported: ["client_secret_post"],
        },
        "unsupported-client-auth-method",
      ],
      [
        {
          issuer: "https://as.example.com",
          token_endpoint: "https://as.example.com/token",
          grant_types_supported: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
          authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"],
          token_endpoint_auth_methods_supported: ["private_key_jwt"],
          token_endpoint_auth_signing_alg_values_supported: ["ES256"],
        },
        "unsupported-client-auth-signing-alg",
      ],
    ] as const) {
      const service = await createService({
        grant,
        fetchImpl: createIdentityFetch({
          "https://as.example.com/.well-known/oauth-authorization-server": Response.json(body),
        }),
      });
      expect(
        must(
          await service.exchangeIdentityGrant({
            resource: "https://rs.example.com/mcp",
            response: bearerChallenge(),
            principal: "user_1",
          }),
        ),
      ).toEqual({ kind: "unsupported", reason });
    }

    const authServerFetchError = await createService({
      grant,
      fetchImpl: createIdentityFetch({
        "https://as.example.com/.well-known/oauth-authorization-server": new Error("offline"),
      }),
    });
    expect(
      errorOf(
        await authServerFetchError.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_metadata_not_found");

    for (const response of [
      new Response(null, { status: 404 }),
      new Response("missing", { status: 404 }),
      textJsonResponse("{"),
    ]) {
      const service = await createService({
        grant,
        fetchImpl: createIdentityFetch({
          "https://as.example.com/.well-known/oauth-authorization-server": response,
        }),
      });
      expect(
        must(
          await service.exchangeIdentityGrant({
            resource: "https://rs.example.com/mcp",
            response: bearerChallenge(),
            principal: "user_1",
          }),
        ),
      ).toEqual({ kind: "unsupported", reason: "oauth-metadata-not-found" });
    }
  });

  it("covers resolvers, default client id, selected AS, and token failures", async () => {
    const selectedGrant = await createGrant({
      clientId: ({ authorizationServerIssuer }) => `client:${authorizationServerIssuer}`,
      subject: ({ path, principal }) => `${path}:${principal}`,
      selectAuthorizationServer: ({ authorizationServers }) => authorizationServers[1]!,
      requireGrantProfile: false,
    });
    const selectedFetch = createIdentityFetch({
      "https://rs.example.com/.well-known/oauth-protected-resource/mcp": Response.json({
        resource: "https://rs.example.com/mcp",
        authorization_servers: ["https://unused.example.com", "https://as.example.com"],
      }),
    });
    const selected = await createService({ grant: selectedGrant, fetchImpl: selectedFetch });
    expect(
      must(
        await selected.exchangeIdentityGrant({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");

    const defaultClient = await createService({
      grant: await createGrant({ clientId: undefined }),
      defaultClientId: "default-client",
    });
    expect(
      must(
        await defaultClient.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");

    for (const grant of [
      await createGrant({ subject: () => Promise.reject(new Error("subject failed")) }),
      await createGrant({ clientId: () => Promise.reject(new Error("client failed")) }),
      await createGrant({
        selectAuthorizationServer: () => Promise.reject(new Error("select failed")),
      }),
      await createGrant({ clientId: undefined }),
      await createGrant({
        signingKey: {
          privateJwk: {
            kty: "RSA",
            n: "bad",
            e: "AQAB",
            d: "bad",
          },
        },
      }),
    ]) {
      const service = await createService({ grant });
      expect(
        (
          await service.exchangeIdentityGrant({
            resource: "https://rs.example.com/mcp",
            response: bearerChallenge(),
            principal: "user_1",
          })
        ).ok,
      ).toBe(false);
    }

    const tokenRequestFailure = await createService({
      grant: await createGrant(),
      fetchImpl: createIdentityFetch({
        "https://as.example.com/token": new Error("token offline"),
      }),
    });
    expect(
      errorOf(
        await tokenRequestFailure.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_token_request_failed");

    const tokenResponseFailure = await createService({
      grant: await createGrant(),
      fetchImpl: createIdentityFetch({}, { token_type: "Bearer" }),
    });
    expect(
      errorOf(
        await tokenResponseFailure.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_token_response_failed");

    const signSpy = vi.spyOn(crypto.subtle, "sign").mockRejectedValueOnce(new Error("sign failed"));
    const signingFailure = await createService({ grant: await createGrant() });
    expect(
      errorOf(
        await signingFailure.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_signing_failed");
    signSpy.mockRestore();

    const noKidNoScopes = await createService({
      grant: await createGrant({ omitKid: true }),
      classification: {
        kind: "auth-required",
        scheme: "bearer",
        scopes: [],
      },
    });
    expect(
      must(
        await noKidNoScopes.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");
    expect(must(noKidNoScopes.createIdentityJwksDocument()).keys[0]).not.toHaveProperty("kid");

    vi.stubGlobal("fetch", createIdentityFetch());
    const globalFetchService = createIdentityGrantService({
      identityGrant: await createGrant(),
      clock: () => NOW,
      classifyResponse: async () =>
        ok({
          ...CLASSIFIED,
          resourceMetadataUrl: new URL(
            "https://rs.example.com/.well-known/oauth-protected-resource",
          ),
        }),
    });
    expect(
      must(
        await globalFetchService.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge("https://rs.example.com/.well-known/oauth-protected-resource"),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");

    const dpopToken = await createService({
      grant: await createGrant(),
      fetchImpl: createIdentityFetch(
        {},
        {
          access_token: "dpop-access",
          token_type: "DPoP",
        },
      ),
    });
    expect(
      must(
        await dpopToken.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).authorization,
    ).toBe("dpop dpop-access");

    const originalImportKey = crypto.subtle.importKey.bind(crypto.subtle);
    let importCalls = 0;
    const importSpy = vi.spyOn(crypto.subtle, "importKey").mockImplementation((...args) => {
      importCalls += 1;
      if (importCalls === 2) {
        return Promise.reject(new Error("second import failed"));
      }
      return originalImportKey(...args);
    });
    const secondImportFailure = await createService({ grant: await createGrant() });
    expect(
      errorOf(
        await secondImportFailure.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).code,
    ).toBe("oauth/identity_signing_failed");
    importSpy.mockRestore();
  });

  it("covers high-level challenge resolution and scoped identity helpers", async () => {
    const encryptionKey = await mustAsync(deriveEncryptionKey(TEST_KEY_MATERIAL));
    const agentPw = must(
      await createAgentPw({
        db: await createTestDb(),
        encryptionKey,
        oauthFetch: createIdentityFetch(),
        identityGrant: await createGrant(),
      }),
    );

    expect(
      must(
        await agentPw.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: { status: 200, headers: {} },
          principal: "user_1",
        }),
      ),
    ).toEqual({
      kind: "unresolved",
      classification: { kind: "none" },
      attempted: { oauthRefresh: false, identityGrant: false },
      reason: "not-auth-challenge",
    });

    let challengeReads = 0;
    expect(
      must(
        await agentPw.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: {
            status: 401,
            headers: {
              get "www-authenticate"() {
                challengeReads += 1;
                return challengeReads <= 2 ? 'Bearer scope="mcp.read"' : undefined;
              },
            },
          },
          principal: "user_1",
          refreshOAuth: false,
        }),
      ).reason,
    ).toBe("not-auth-challenge");

    await mustAsync(
      agentPw.credentials.put({
        path: "org_alpha.connections.headers",
        auth: { kind: "headers", resource: "https://rs.example.com/mcp" },
        secret: { headers: { Authorization: "Bearer stored" } },
      }),
    );
    expect(
      must(
        await agentPw.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.headers",
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          headers: { "X-Trace": "trace-1" },
        }),
      ),
    ).toEqual({
      kind: "resolved",
      source: "oauth-refresh",
      headers: {
        Authorization: "Bearer stored",
        "X-Trace": "trace-1",
      },
    });

    const disabled = must(
      await createAgentPw({
        db: await createTestDb(),
        encryptionKey,
      }),
    );
    expect(
      must(
        await disabled.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          principal: "user_1",
          refreshOAuth: false,
        }),
      ).reason,
    ).toBe("identity-grant-disabled");

    const unsupported = must(
      await createAgentPw({
        db: await createTestDb(),
        encryptionKey,
        oauthFetch: createIdentityFetch({
          "https://as.example.com/.well-known/oauth-authorization-server": Response.json({
            issuer: "https://as.example.com",
            token_endpoint: "https://as.example.com/token",
            grant_types_supported: [],
          }),
        }),
        identityGrant: await createGrant(),
      }),
    );
    expect(
      must(
        await unsupported.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: CHALLENGE,
          principal: "user_1",
          refreshOAuth: false,
        }),
      ).reason,
    ).toBe("identity-grant-unsupported");

    const scoped = agentPw.scope({ rights: [{ action: "credential.use", root: "org_alpha" }] });
    expect(
      must(
        await scoped.connect.exchangeIdentityGrant({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");
    expect(
      must(
        await scoped.connect.exchangeIdentityGrant({
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).kind,
    ).toBe("exchanged");
    expect(
      must(
        await scoped.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
          refreshOAuth: false,
        }),
      ).kind,
    ).toBe("resolved");
    expect(
      errorOf(
        await agentPw.scope({ rights: [] }).connect.exchangeIdentityGrant({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).type,
    ).toBe("Authorization");
    expect(
      errorOf(
        await agentPw.scope({ rights: [] }).connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
        }),
      ).type,
    ).toBe("Authorization");

    expect(
      errorOf(
        await agentPw.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: {
            status: 403,
            headers: {
              "www-authenticate":
                'Bearer error="insufficient_scope", resource_metadata="not-a-url"',
            },
          },
        }),
      ).code,
    ).toBe("oauth/scope_challenge_parse_failed");

    const badSigningAgent = must(
      await createAgentPw({
        db: await createTestDb(),
        encryptionKey,
        oauthFetch: createIdentityFetch(),
        identityGrant: await createGrant({
          signingKey: {
            privateJwk: {
              kty: "RSA",
              n: "bad",
              e: "AQAB",
              d: "bad",
            },
          },
        }),
      }),
    );
    expect(
      errorOf(
        await badSigningAgent.connect.resolveChallengeHeaders({
          path: "org_alpha.connections.rs",
          resource: "https://rs.example.com/mcp",
          response: bearerChallenge(),
          principal: "user_1",
          refreshOAuth: false,
        }),
      ).code,
    ).toBe("oauth/identity_signing_failed");
  }, 15_000);
});
