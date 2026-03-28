import { afterEach, describe, expect, it, vi } from "vitest";
import {
  extractTokenFacts,
  mintToken,
  restrictToken,
  authorizeRequest,
} from "agent.pw/biscuit";
import { rootsForAction, rootsForActions } from "agent.pw/rules";
import { persistenceError, isAgentPwError } from "../packages/server/src/errors";
import { mergeHeaders } from "../packages/server/src/lib/connect-headers";
import {
  decryptCredentials,
  deriveEncryptionKey,
  encryptCredentials,
  encryptSecret,
  importAesKey,
} from "../packages/server/src/lib/credentials-crypto";
import {
  anyResourcePatternMatches,
  resourcePatternMatches,
} from "../packages/server/src/resource-patterns";
import { BISCUIT_PRIVATE_KEY, PUBLIC_KEY_HEX } from "./setup";
import { errorOf, errorOfAsync, must, mustAsync } from "./support/results";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("helper coverage", () => {
  it("covers helper error factories and invalid resource pattern propagation", async () => {
    const persistence = persistenceError("write", "persist failed", { path: "acme.docs" });
    expect(persistence).toEqual({
      type: "Persistence",
      operation: "write",
      message: "persist failed",
      path: "acme.docs",
    });
    expect(isAgentPwError(persistence)).toBe(true);

    expect(errorOf(resourcePatternMatches("/relative/*", "https://example.com")).message).toBe(
      "Invalid resource pattern '/relative/*'",
    );
    expect(errorOf(resourcePatternMatches("https://example.com/*", "not-a-url")).message).toBe(
      "Invalid resource 'not-a-url'",
    );
    expect(
      (
        await errorOfAsync(
          anyResourcePatternMatches(["/relative/*", "https://ok.example.com/*"], "https://ok.example.com"),
        )
      ).message,
    ).toBe("Invalid resource pattern '/relative/*'");
  });

  it("covers global rule roots, auth header merging, and root biscuit paths", () => {
    const rights = [
      { action: "credential.use" as const },
      { action: "profile.manage" as const },
      { action: "credential.manage" as const, root: "acme" },
    ];

    expect(rootsForAction(rights, "credential.use")).toEqual([]);
    expect(rootsForActions(rights, ["credential.use", "profile.manage"])).toEqual([]);

    expect(
      mergeHeaders({
        existingHeaders: { Authorization: "Bearer old", "X-Test": "1" },
        headers: { "X-New": "2" },
        preserveExistingHeaders: true,
      }),
    ).toEqual({
      Authorization: "Bearer old",
      "X-Test": "1",
      "X-New": "2",
    });
    expect(
      mergeHeaders({
        headers: { "X-Test": "1" },
        oauthHeaders: {
          Authorization: "Bearer oauth",
          "Proxy-Authorization": "Basic proxy",
        },
      }),
    ).toEqual({
      "X-Test": "1",
      Authorization: "Bearer oauth",
      "Proxy-Authorization": "Basic proxy",
    });

    const token = must(
      restrictToken(
        mintToken(BISCUIT_PRIVATE_KEY, "root-user", [{ action: "credential.use" }]),
        PUBLIC_KEY_HEX,
        [{ services: "github", methods: "GET", paths: "/" }],
      ),
    );

    expect(
      authorizeRequest(token, PUBLIC_KEY_HEX, "github", "GET", "/repos/1").authorized,
    ).toBe(true);
    expect(extractTokenFacts(token, PUBLIC_KEY_HEX)).toEqual(
      expect.objectContaining({
        rights: [{ action: "credential.use" }],
      }),
    );
  });

  it("covers crypto failure branches", async () => {
    const digestSpy = vi
      .spyOn(crypto.subtle, "digest")
      .mockRejectedValueOnce(new Error("digest failed"));
    expect((await errorOfAsync(deriveEncryptionKey("seed"))).message).toBe(
      "Failed to derive encryption key",
    );
    digestSpy.mockRestore();

    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const importSpy = vi
      .spyOn(crypto.subtle, "importKey")
      .mockRejectedValueOnce(new Error("import failed"));
    expect((await errorOfAsync(importAesKey(encryptionKey))).message).toBe(
      "Failed to import AES key",
    );
    importSpy.mockRestore();

    expect(
      (await errorOfAsync(
        encryptCredentials(Buffer.from("short").toString("base64"), {
          headers: { Authorization: "Bearer short" },
        }),
      )).message,
    ).toBe("Encryption key must be 32 bytes");
    expect(
      (await errorOfAsync(encryptSecret(Buffer.from("short").toString("base64"), "secret"))).message,
    ).toBe("Encryption key must be 32 bytes");

    const encryptSpy = vi
      .spyOn(crypto.subtle, "encrypt")
      .mockRejectedValueOnce(new Error("encrypt failed"));
    expect(
      (await errorOfAsync(
        encryptCredentials(encryptionKey, {
          headers: { Authorization: "Bearer secret" },
        }),
      )).message,
    ).toBe("Failed to encrypt credentials");
    encryptSpy.mockRestore();

    const encryptSecretSpy = vi
      .spyOn(crypto.subtle, "encrypt")
      .mockRejectedValueOnce(new Error("secret failed"));
    expect((await errorOfAsync(encryptSecret(encryptionKey, "secret"))).message).toBe(
      "Failed to encrypt secret",
    );
    encryptSecretSpy.mockRestore();

    expect((await errorOfAsync(decryptCredentials(encryptionKey, Buffer.alloc(28, 1)))).message).toBe(
      "Failed to decrypt credentials",
    );
    expect(
      (await errorOfAsync(
        decryptCredentials(Buffer.from("short").toString("base64"), Buffer.alloc(28, 1)),
      )).message,
    ).toBe("Encryption key must be 32 bytes");

    const nonJson = await mustAsync(encryptSecret(encryptionKey, "not-json"));
    expect((await errorOfAsync(decryptCredentials(encryptionKey, nonJson))).message).toBe(
      "Failed to parse decrypted credentials",
    );

    const invalidShape = await mustAsync(
      encryptSecret(
        encryptionKey,
        JSON.stringify({
          headers: { Authorization: "Bearer secret" },
          extra: true,
        }),
      ),
    );
    expect((await errorOfAsync(decryptCredentials(encryptionKey, invalidShape))).message).toBe(
      "Failed to parse decrypted credentials",
    );
  });
});
