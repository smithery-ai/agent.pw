import { createAgentPw } from "agent.pw";
import {
  IDENTITY_ASSERTION_GRANT_PROFILE,
  IDENTITY_ASSERTION_JWT_TYPE,
  JWT_BEARER_GRANT_TYPE,
} from "agent.pw/identity";
import { describe, expect, it } from "vitest";
import { createTestDb } from "./setup";
import { must } from "./support/results";

function decodeJwtPart(token: string, index: 0 | 1) {
  return JSON.parse(Buffer.from(token.split(".")[index]!, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
}

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

function createIdentityFetch(opts?: { omitGrantProfile?: boolean }) {
  const tokenRequests: Array<{
    assertion: string;
    clientAssertion: string;
    body: URLSearchParams;
  }> = [];

  const fetchImpl: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    if (url === "https://rs.example.com/.well-known/oauth-protected-resource") {
      return Response.json({
        resource: "https://rs.example.com/mcp",
        authorization_servers: ["https://as.example.com"],
      });
    }

    if (url === "https://as.example.com/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: "https://as.example.com",
        token_endpoint: "https://as.example.com/token",
        grant_types_supported: [JWT_BEARER_GRANT_TYPE],
        authorization_grant_profiles_supported: opts?.omitGrantProfile
          ? []
          : [IDENTITY_ASSERTION_GRANT_PROFILE],
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
        token_endpoint_auth_signing_alg_values_supported: ["RS256"],
      });
    }

    if (url === "https://as.example.com/token") {
      const body =
        init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(typeof init?.body === "string" ? init.body : undefined);
      tokenRequests.push({
        assertion: body.get("assertion") ?? "",
        clientAssertion: body.get("client_assertion") ?? "",
        body,
      });
      return Response.json({
        access_token: "downstream-access-1",
        token_type: "Bearer",
        expires_in: 120,
        scope: "mcp.read mcp.write",
      });
    }

    throw new Error(`Unexpected identity fetch: ${url}`);
  };

  return { fetchImpl, tokenRequests };
}

async function createIdentityAgent(opts?: { omitGrantProfile?: boolean }) {
  const { fetchImpl, tokenRequests } = createIdentityFetch(opts);
  const agentPw = must(
    await createAgentPw({
      db: await createTestDb(),
      oauthFetch: fetchImpl,
      clock: () => new Date("2026-04-29T12:00:00.000Z"),
      identityGrant: {
        issuer: "https://issuer.example.com",
        clientId: "identity-client",
        signingKey: {
          privateJwk: await createSigningKey(),
        },
        subject: ({ principal }) => `subject:${principal}`,
      },
    }),
  );

  return { agentPw, tokenRequests };
}

function bearerChallenge() {
  return {
    status: 401,
    headers: {
      "www-authenticate":
        'Bearer resource_metadata="https://rs.example.com/.well-known/oauth-protected-resource", scope="mcp.read mcp.write"',
    },
  };
}

describe("connect identity grant exchange", () => {
  it("exchanges an ID-JAG for downstream retry headers", async () => {
    const { agentPw, tokenRequests } = await createIdentityAgent();

    const exchanged = must(
      await agentPw.connect.exchangeIdentityGrant({
        resource: "https://rs.example.com/mcp",
        response: bearerChallenge(),
        principal: "user_1",
        headers: {
          authorization: "Bearer stale",
          "X-Trace": "trace-1",
        },
      }),
    );

    expect(exchanged).toEqual(
      expect.objectContaining({
        kind: "exchanged",
        authorization: "Bearer downstream-access-1",
        accessToken: "downstream-access-1",
        tokenType: "Bearer",
        expiresIn: 120,
        scope: "mcp.read mcp.write",
        source: "identity-jag",
        headers: {
          Authorization: "Bearer downstream-access-1",
          "X-Trace": "trace-1",
        },
      }),
    );

    expect(tokenRequests).toHaveLength(1);
    expect(tokenRequests[0]?.body.get("grant_type")).toBe(JWT_BEARER_GRANT_TYPE);

    const header = decodeJwtPart(tokenRequests[0]!.assertion, 0);
    const payload = decodeJwtPart(tokenRequests[0]!.assertion, 1);
    expect(header).toEqual(
      expect.objectContaining({
        alg: "RS256",
        kid: "identity-key-1",
        typ: IDENTITY_ASSERTION_JWT_TYPE,
      }),
    );
    expect(payload).toEqual(
      expect.objectContaining({
        iss: "https://issuer.example.com",
        sub: "subject:user_1",
        aud: "https://as.example.com",
        client_id: "identity-client",
        resource: "https://rs.example.com/mcp",
        scope: "mcp.read mcp.write",
      }),
    );
    expect(payload.jti).toEqual(expect.any(String));
    expect(payload.iat).toBe(1777464000);
    expect(payload.exp).toBe(1777464060);

    const clientAssertionPayload = decodeJwtPart(tokenRequests[0]!.clientAssertion, 1);
    expect(clientAssertionPayload.aud).toBe("https://as.example.com/token");
  });

  it("resolves retry headers through the high-level challenge helper", async () => {
    const { agentPw } = await createIdentityAgent();

    const resolved = must(
      await agentPw.connect.resolveChallengeHeaders({
        path: "org_alpha.connections.rs",
        resource: "https://rs.example.com/mcp",
        response: bearerChallenge(),
        principal: "user_1",
        headers: {
          "X-Trace": "trace-1",
        },
      }),
    );

    expect(resolved).toEqual({
      kind: "resolved",
      source: "identity-jag",
      headers: {
        Authorization: "Bearer downstream-access-1",
        "X-Trace": "trace-1",
      },
    });
  });

  it("returns unsupported instead of throwing for missing grant profile support", async () => {
    const { agentPw } = await createIdentityAgent({ omitGrantProfile: true });

    const exchanged = must(
      await agentPw.connect.exchangeIdentityGrant({
        resource: "https://rs.example.com/mcp",
        response: bearerChallenge(),
        principal: "user_1",
      }),
    );

    expect(exchanged).toEqual({
      kind: "unsupported",
      reason: "unsupported-grant-profile",
    });
  });

  it("does not try ID-JAG without a principal", async () => {
    const { agentPw } = await createIdentityAgent();

    const resolved = must(
      await agentPw.connect.resolveChallengeHeaders({
        path: "org_alpha.connections.rs",
        resource: "https://rs.example.com/mcp",
        response: bearerChallenge(),
      }),
    );

    expect(resolved).toEqual({
      kind: "unresolved",
      classification: expect.objectContaining({ kind: "auth-required" }),
      attempted: {
        oauthRefresh: true,
        identityGrant: false,
      },
      reason: "oauth-refresh-unavailable",
    });
  });
});
