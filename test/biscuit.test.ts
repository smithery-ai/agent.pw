import { describe, expect, it } from "vitest";
import { Biscuit, PrivateKey } from "@smithery/biscuit";
import {
  authorizeRequest,
  compileRulesToBiscuit,
  extractTokenFacts,
  extractUserId,
  generateKeyPairHex,
  getPublicKey,
  getPublicKeyHex,
  getRevocationIds,
  hashToken,
  mintToken,
  parseTtlSeconds,
  restrictToken,
  stripPrefix,
  subjectFactsToExtraFacts,
} from "agent.pw/biscuit";
import { BISCUIT_PRIVATE_KEY, ORG_TOKEN, PUBLIC_KEY_HEX, TEST_ORG_ID } from "./setup";
import { errorOf, must } from "./support/results";

function buildCustomToken(code: string) {
  const builder = Biscuit.builder();
  builder.addCode(code);
  return builder.build(PrivateKey.fromString(BISCUIT_PRIVATE_KEY)).toBase64();
}

describe("biscuit helpers", () => {
  it("strips prefixes and parses TTL values", () => {
    expect(stripPrefix("apw_abc")).toBe("abc");
    expect(stripPrefix("plain")).toBe("plain");
    expect(must(parseTtlSeconds(60))).toBe(60);
    expect(must(parseTtlSeconds("30"))).toBe(30);
    expect(must(parseTtlSeconds("5s"))).toBe(5);
    expect(must(parseTtlSeconds("5m"))).toBe(300);
    expect(must(parseTtlSeconds("2h"))).toBe(7200);
    expect(must(parseTtlSeconds("1d"))).toBe(86400);
    expect(errorOf(parseTtlSeconds("soon")).message).toBe("Invalid TTL format: soon");
  });

  it("mints tokens, extracts facts, and derives public metadata", async () => {
    const token = mintToken(
      BISCUIT_PRIVATE_KEY,
      "user_test_123",
      [{ action: "credential.use", root: `/${TEST_ORG_ID}` }],
      [`org_id("${TEST_ORG_ID}")`, "  ", 'scope("repo");', 'scope("write")', 'custom("value")'],
    );

    const facts = extractTokenFacts(token, PUBLIC_KEY_HEX);
    expect(facts).toEqual({
      rights: [{ action: "credential.use", root: `/${TEST_ORG_ID}` }],
      userId: "user_test_123",
      orgId: TEST_ORG_ID,
      homePath: null,
      scopes: ["repo", "write"],
    });
    expect(extractUserId(token, PUBLIC_KEY_HEX)).toBe("user_test_123");
    expect(getPublicKeyHex(BISCUIT_PRIVATE_KEY)).toBe(PUBLIC_KEY_HEX);
    expect(getRevocationIds(token, PUBLIC_KEY_HEX).length).toBeGreaterThan(0);
    await expect(hashToken(token)).resolves.toMatch(/^[0-9a-f]{64}$/);
    expect(
      subjectFactsToExtraFacts({
        orgId: TEST_ORG_ID,
        homePath: `/${TEST_ORG_ID}`,
        scopes: ["repo"],
      }),
    ).toEqual([`org_id("${TEST_ORG_ID}");`, `home_path("/${TEST_ORG_ID}");`, 'scope("repo");']);
    expect(subjectFactsToExtraFacts({ orgId: TEST_ORG_ID })).toEqual([`org_id("${TEST_ORG_ID}");`]);
    expect(subjectFactsToExtraFacts(undefined)).toEqual([]);
  });

  it("restricts tokens against service, method, path, and TTL constraints", () => {
    const unrestricted = must(restrictToken(ORG_TOKEN, PUBLIC_KEY_HEX, []));
    expect(unrestricted).toBe(ORG_TOKEN);

    const restricted = must(
      restrictToken(ORG_TOKEN, PUBLIC_KEY_HEX, [
        {
          hosts: "api.linear.app",
          services: ["github", "gitlab"],
          methods: ["GET", "POST"],
          paths: ["/user", "/repos"],
          ttl: "5m",
        },
        { services: "linear", methods: "HEAD", paths: "/graphql", ttl: 600 },
      ]),
    );

    expect(restricted).not.toBe(ORG_TOKEN);
    expect(
      authorizeRequest(restricted, PUBLIC_KEY_HEX, "github", "GET", "/user", {
        host: "api.linear.app",
      }).authorized,
    ).toBe(true);
    expect(
      authorizeRequest(restricted, PUBLIC_KEY_HEX, "gitlab", "POST", "/repos/1", {
        host: "api.linear.app",
      }).authorized,
    ).toBe(true);
    expect(
      authorizeRequest(restricted, PUBLIC_KEY_HEX, "linear", "HEAD", "/graphql").authorized,
    ).toBe(true);
    expect(
      authorizeRequest(restricted, PUBLIC_KEY_HEX, "github", "DELETE", "/user").authorized,
    ).toBe(false);
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, "github", "GET", "/admin").authorized).toBe(
      false,
    );
    expect(authorizeRequest(restricted, PUBLIC_KEY_HEX, "other", "GET", "/user").authorized).toBe(
      false,
    );
    expect(authorizeRequest("bad-token", PUBLIC_KEY_HEX, "github", "GET", "/user")).toEqual({
      authorized: false,
      error: expect.any(String),
    });
  });

  it("returns empty facts for invalid tokens and generates key pairs", () => {
    expect(extractTokenFacts("bad-token", PUBLIC_KEY_HEX)).toEqual({
      rights: [],
      userId: null,
      orgId: null,
      homePath: null,
      scopes: [],
    });

    const pair = generateKeyPairHex();
    expect(pair.privateKey).toMatch(/^ed25519-private\//);
    expect(pair.publicKey).toMatch(/^ed25519\//);
  });

  it("extracts bare facts only", () => {
    const bareToken = buildCustomToken(
      [
        'user_id("legacy-user");',
        'org_id("legacy-org");',
        'right("/legacy-org", "credential.use");',
        'scope("repo");',
      ].join("\n"),
    );

    expect(extractTokenFacts(bareToken, PUBLIC_KEY_HEX)).toEqual({
      rights: [{ action: "credential.use", root: "/legacy-org" }],
      userId: "legacy-user",
      orgId: "legacy-org",
      homePath: null,
      scopes: ["repo"],
    });

    const withHomePath = buildCustomToken(
      ['user_id("legacy-user");', 'home_path("/legacy-org");'].join("\n"),
    );
    expect(extractTokenFacts(withHomePath, PUBLIC_KEY_HEX)).toEqual(
      expect.objectContaining({
        homePath: "/legacy-org",
      }),
    );

    const orgOnlyToken = buildCustomToken('org_id("org-only");');
    expect(extractUserId(orgOnlyToken, PUBLIC_KEY_HEX)).toBe("org-only");
  });

  it("authorizes bare identity facts", () => {
    const bareToken = buildCustomToken(
      [
        'user_id("legacy-user");',
        'org_id("legacy-org");',
        'right("/legacy-org", "profile.manage");',
      ].join("\n"),
    );

    expect(
      authorizeRequest(
        bareToken,
        PUBLIC_KEY_HEX,
        "api.example.com",
        "PUT",
        "/cred_profiles/linear",
      ),
    ).toEqual({ authorized: true });
  });

  it("compiles rule grants and constraints into biscuits", () => {
    const compiled = must(
      compileRulesToBiscuit({
        privateKeyHex: BISCUIT_PRIVATE_KEY,
        subject: "compiled-user",
        rights: [{ action: "credential.use", root: "/org_alpha" }],
        constraints: [{ methods: "GET", paths: "/org_alpha" }],
        extraFacts: ['org_id("org_alpha")'],
      }),
    );

    expect(extractTokenFacts(compiled, PUBLIC_KEY_HEX)).toEqual(
      expect.objectContaining({
        userId: "compiled-user",
        orgId: "org_alpha",
        rights: [{ action: "credential.use", root: "/org_alpha" }],
      }),
    );

    const unconstrained = must(
      compileRulesToBiscuit({
        privateKeyHex: BISCUIT_PRIVATE_KEY,
        subject: "compiled-user",
        rights: [{ action: "credential.use", root: "/org_alpha" }],
      }),
    );
    expect(extractTokenFacts(unconstrained, PUBLIC_KEY_HEX)).toEqual(
      expect.objectContaining({
        userId: "compiled-user",
      }),
    );
  });

  it("emits bare identity facts and plain ambient request facts", () => {
    const token = mintToken(
      BISCUIT_PRIVATE_KEY,
      "user_test_123",
      [{ action: "credential.manage", root: `/${TEST_ORG_ID}` }],
      [`org_id("${TEST_ORG_ID}")`],
    );
    const publicKey = getPublicKey(BISCUIT_PRIVATE_KEY);
    const biscuit = Biscuit.fromBase64(stripPrefix(token), publicKey);
    const authority = biscuit.getBlockSource(0);
    const authorityLines = authority
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    expect(authorityLines).toContain('user_id("user_test_123");');
    expect(authorityLines).toContain(`right("/${TEST_ORG_ID}", "credential.manage");`);
    expect(authorityLines).not.toContain('right("credential.manage");');

    const restricted = must(
      restrictToken(token, PUBLIC_KEY_HEX, [
        { services: "github", methods: "GET", paths: "/user" },
      ]),
    );
    const attenuated = Biscuit.fromBase64(stripPrefix(restricted), publicKey);
    const block = attenuated.getBlockSource(1);

    expect(block).toContain("resource($r)");
    expect(block).toContain("operation($op)");
    expect(block).toContain("path($p)");
    expect(block).not.toContain("requested_root");
  });
});
