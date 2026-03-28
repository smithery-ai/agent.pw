import { afterEach, describe, expect, it, vi } from "vitest";
import {
  decryptCredentials,
  deriveEncryptionKey,
  encryptCredentials,
  encryptSecret,
  importAesKey,
} from "../packages/server/src/lib/credentials-crypto";
import { BISCUIT_PRIVATE_KEY } from "./setup";
import { errorOfAsync, mustAsync } from "./support/results";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("helper coverage", () => {
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
      (
        await errorOfAsync(
          encryptCredentials(Buffer.from("short").toString("base64"), {
            headers: { Authorization: "Bearer short" },
          }),
        )
      ).message,
    ).toBe("Encryption key must be 32 bytes");
    expect(
      (await errorOfAsync(encryptSecret(Buffer.from("short").toString("base64"), "secret")))
        .message,
    ).toBe("Encryption key must be 32 bytes");

    const encryptSpy = vi
      .spyOn(crypto.subtle, "encrypt")
      .mockRejectedValueOnce(new Error("encrypt failed"));
    expect(
      (
        await errorOfAsync(
          encryptCredentials(encryptionKey, {
            headers: { Authorization: "Bearer secret" },
          }),
        )
      ).message,
    ).toBe("Failed to encrypt credentials");
    encryptSpy.mockRestore();

    const encryptSecretSpy = vi
      .spyOn(crypto.subtle, "encrypt")
      .mockRejectedValueOnce(new Error("secret failed"));
    expect((await errorOfAsync(encryptSecret(encryptionKey, "secret"))).message).toBe(
      "Failed to encrypt secret",
    );
    encryptSecretSpy.mockRestore();

    expect(
      (await errorOfAsync(decryptCredentials(encryptionKey, Buffer.alloc(28, 1)))).message,
    ).toBe("Failed to decrypt credentials");
    expect(
      (
        await errorOfAsync(
          decryptCredentials(Buffer.from("short").toString("base64"), Buffer.alloc(28, 1)),
        )
      ).message,
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
