import { describe, expect, it } from "vitest";
import { Biscuit, PrivateKey } from "@smithery/biscuit";
import {
  appendTokenBlocks,
  authorizeRequest,
  extractAttenuationBlockSources,
  extractAuthorityExtraFacts,
  extractTokenExpiry,
  extractTokenFacts,
  mintDescendantToken,
  mintToken,
  restrictToken,
} from "agent.pw/biscuit";
import { BISCUIT_PRIVATE_KEY, PUBLIC_KEY_HEX } from "./setup";
import { errorOf, must } from "./support/results";

function buildCustomToken(code: string) {
  const builder = Biscuit.builder();
  builder.addCode(code);
  return builder.build(PrivateKey.fromString(BISCUIT_PRIVATE_KEY)).toBase64();
}

describe("biscuit advanced helpers", () => {
  it("extracts authority facts and attenuation blocks", () => {
    const parent = mintToken(
      BISCUIT_PRIVATE_KEY,
      "user_alpha",
      [{ action: "credential.use", root: "org_alpha" }],
      ['org_id("org_alpha")', 'home_path("org_alpha")', 'scope("repo")', 'custom("value")'],
    );
    const appended = appendTokenBlocks(parent, PUBLIC_KEY_HEX, [
      'check if operation($op), ["GET"].contains($op);',
      'check if host($host), ["api.linear.app"].contains($host);',
    ]);

    expect(extractAuthorityExtraFacts(appended, PUBLIC_KEY_HEX)).toEqual([
      'org_id("org_alpha");',
      'home_path("org_alpha");',
      'scope("repo");',
      'custom("value");',
    ]);
    expect(extractAttenuationBlockSources(appended, PUBLIC_KEY_HEX)).toEqual([
      'check if operation($op), ["GET"].contains($op);',
      'check if host($host), ["api.linear.app"].contains($host);',
    ]);
    expect(appendTokenBlocks(parent, PUBLIC_KEY_HEX, [])).toBe(parent);
    expect(appendTokenBlocks(parent, PUBLIC_KEY_HEX, ["   "])).toBe(parent);
  });

  it("mints descendant tokens and derives the narrowest expiry", () => {
    const parent = mintToken(
      BISCUIT_PRIVATE_KEY,
      "user_alpha",
      [{ action: "credential.use", root: "org_alpha" }],
      ['org_id("org_alpha")', 'scope("repo")'],
    );

    const child = must(
      mintDescendantToken(
        BISCUIT_PRIVATE_KEY,
        PUBLIC_KEY_HEX,
        parent,
        [{ action: "credential.use", root: "org_alpha.ws_engineering" }],
        [{ methods: "GET", paths: "/org_alpha/ws_engineering", ttl: "1m" }],
      ),
    );

    expect(extractTokenFacts(child, PUBLIC_KEY_HEX)).toEqual(
      expect.objectContaining({
        userId: "user_alpha",
        orgId: "org_alpha",
        scopes: ["repo"],
        rights: [{ action: "credential.use", root: "org_alpha.ws_engineering" }],
      }),
    );

    const expiry = extractTokenExpiry(child, PUBLIC_KEY_HEX);
    expect(expiry).toBeInstanceOf(Date);
    expect(expiry?.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);

    expect(
      authorizeRequest(
        child,
        PUBLIC_KEY_HEX,
        "api.linear.app",
        "GET",
        "/org_alpha/ws_engineering/task",
        {
          action: "credential.use",
          host: "api.linear.app",
          requestedRoot: "org_alpha.ws_engineering",
        },
      ).authorized,
    ).toBe(true);

    const rooted = mintToken(BISCUIT_PRIVATE_KEY, "user_alpha", [
      { action: "credential.use", root: "org_alpha" },
    ]);
    const rootRestricted = must(
      restrictToken(rooted, PUBLIC_KEY_HEX, [
        {
          actions: "credential.use",
          roots: "org_alpha.ws_engineering",
          methods: "GET",
          paths: "/org_alpha/ws_engineering",
        },
      ]),
    );
    expect(
      authorizeRequest(
        rootRestricted,
        PUBLIC_KEY_HEX,
        "api.linear.app",
        "GET",
        "/org_alpha/ws_engineering/task",
        {
          action: "credential.use",
          host: "api.linear.app",
          requestedRoot: "org_alpha.ws_engineering",
        },
      ).authorized,
    ).toBe(true);
  });

  it("rejects descendant minting without parent identity and ignores bad expiry input", () => {
    const parentWithoutIdentity = buildCustomToken('custom("value");');
    expect(extractTokenExpiry(parentWithoutIdentity, PUBLIC_KEY_HEX)).toBeNull();
    expect(extractTokenExpiry("bad-token", PUBLIC_KEY_HEX)).toBeNull();
    expect(extractTokenFacts(mintToken(BISCUIT_PRIVATE_KEY, "seed-user")).rights).toEqual([]);

    expect(
      errorOf(
        mintDescendantToken(
          BISCUIT_PRIVATE_KEY,
          PUBLIC_KEY_HEX,
          parentWithoutIdentity,
          [{ action: "credential.use", root: "org_alpha" }],
          [],
        ),
      ).message,
    ).toBe("Parent token has no identity");
  });
});
