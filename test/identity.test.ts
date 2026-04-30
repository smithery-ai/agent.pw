import { createAgentPw } from "agent.pw";
import {
  IDENTITY_ASSERTION_GRANT_PROFILE,
  IDENTITY_ASSERTION_JWT_TYPE,
  JWT_BEARER_GRANT_TYPE,
  pairwiseIdentitySubject,
} from "agent.pw/identity";
import { describe, expect, it } from "vitest";
import { createTestDb } from "./setup";
import { must } from "./support/results";

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

describe("identity helpers", () => {
  it("exports ID-JAG constants", () => {
    expect(JWT_BEARER_GRANT_TYPE).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(IDENTITY_ASSERTION_GRANT_PROFILE).toBe("urn:ietf:params:oauth:grant-profile:id-jag");
    expect(IDENTITY_ASSERTION_JWT_TYPE).toBe("oauth-id-jag+jwt");
  });

  it("creates a public JWKS document from the configured private RSA JWK", async () => {
    const agentPw = must(
      await createAgentPw({
        db: await createTestDb(),
        identityGrant: {
          issuer: "https://issuer.example.com",
          clientId: "identity-client",
          signingKey: {
            privateJwk: await createSigningKey(),
          },
          subject: () => "subject-1",
        },
      }),
    );

    const document = must(agentPw.connect.createIdentityJwksDocument());
    expect(document.keys).toHaveLength(1);
    expect(document.keys[0]).toEqual(
      expect.objectContaining({
        kty: "RSA",
        kid: "identity-key-1",
        alg: "RS256",
        use: "sig",
      }),
    );
    expect(document.keys[0]).not.toHaveProperty("d");
    expect(document.keys[0]).not.toHaveProperty("p");
    expect(document.keys[0]).not.toHaveProperty("q");
    expect(document.keys[0]).not.toHaveProperty("dp");
    expect(document.keys[0]).not.toHaveProperty("dq");
    expect(document.keys[0]).not.toHaveProperty("qi");

    const response = must(agentPw.connect.createIdentityJwksResponse());
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");
    await expect(response.json()).resolves.toEqual(document);
  });

  it("returns an input error when JWKS helpers are used without identity grants", async () => {
    const agentPw = must(
      await createAgentPw({
        db: await createTestDb(),
      }),
    );

    const document = agentPw.connect.createIdentityJwksDocument();
    expect(document.ok).toBe(false);
    if (!document.ok) {
      expect(document.error.type).toBe("Input");
    }
  });

  it("derives deterministic pairwise subjects by authorization server by default", async () => {
    const subject = pairwiseIdentitySubject({ secret: "pairwise-secret" });
    const resourceSubject = pairwiseIdentitySubject({
      secret: new TextEncoder().encode("pairwise-secret"),
      sector: "resource",
      info: "test",
    });

    const first = await subject({
      principal: "user_1",
      requestedResource: "https://rs.example.com/mcp",
      protectedResource: "https://rs.example.com/mcp",
      authorizationServerIssuer: "https://as-one.example.com",
      scopes: [],
    });
    const repeated = await subject({
      principal: "user_1",
      requestedResource: "https://rs.example.com/mcp",
      protectedResource: "https://rs.example.com/mcp",
      authorizationServerIssuer: "https://as-one.example.com",
      scopes: [],
    });
    const changed = await subject({
      principal: "user_1",
      requestedResource: "https://rs.example.com/mcp",
      protectedResource: "https://rs.example.com/mcp",
      authorizationServerIssuer: "https://as-two.example.com",
      scopes: [],
    });

    expect(first).toBe(repeated);
    expect(first).not.toBe(changed);
    await expect(
      resourceSubject({
        principal: "user_1",
        requestedResource: "https://rs.example.com/mcp",
        protectedResource: "https://rs.example.com/mcp",
        authorizationServerIssuer: "https://as-one.example.com",
        scopes: [],
      }),
    ).resolves.toEqual(expect.any(String));
  });
});
