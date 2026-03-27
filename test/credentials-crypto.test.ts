import { describe, expect, it } from "vitest";
import {
  buildCredentialHeaders,
  decryptCredentials,
  deriveEncryptionKey,
  encryptCredentials,
  encryptSecret,
  importAesKey,
} from "../packages/server/src/lib/credentials-crypto";
import { BISCUIT_PRIVATE_KEY } from "./setup";
import { mustAsync } from "./support/results";

async function decryptSecretBuffer(encryptionKey: string, encrypted: Buffer) {
  const key = await mustAsync(importAesKey(encryptionKey));
  const iv = encrypted.subarray(0, 12);
  const ciphertext = encrypted.subarray(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

describe("credentials crypto", () => {
  it("derives deterministic AES keys from an application secret", async () => {
    const first = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const second = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const other = await mustAsync(deriveEncryptionKey("ed25519-private/another-secret"));

    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(Buffer.from(first, "base64")).toHaveLength(32);
  });

  it("encrypts and decrypts structured credentials", async () => {
    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const encrypted = await mustAsync(
      encryptCredentials(encryptionKey, {
        headers: { Authorization: "Bearer secret" },
        oauth: {
          accessToken: "access",
          refreshToken: "refresh",
          scopes: "repo",
          tokenType: "bearer",
        },
      }),
    );

    expect(await mustAsync(decryptCredentials(encryptionKey, encrypted))).toEqual({
      headers: { Authorization: "Bearer secret" },
      oauth: {
        accessToken: "access",
        refreshToken: "refresh",
        scopes: "repo",
        tokenType: "bearer",
      },
    });
  });

  it("rejects invalid encryption inputs and can encrypt standalone secrets", async () => {
    const invalidKey = await importAesKey(Buffer.from("short").toString("base64"));
    expect(invalidKey.ok).toBe(false);
    if (!invalidKey.ok) {
      expect(invalidKey.error.message).toBe("Encryption key must be 32 bytes");
    }

    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const invalidCiphertext = await decryptCredentials(encryptionKey, Buffer.alloc(8));
    expect(invalidCiphertext.ok).toBe(false);
    if (!invalidCiphertext.ok) {
      expect(invalidCiphertext.error.message).toBe("Invalid ciphertext");
    }

    const encryptedSecret = await mustAsync(encryptSecret(encryptionKey, "oauth-secret"));
    expect(await decryptSecretBuffer(encryptionKey, encryptedSecret)).toBe("oauth-secret");
  });

  it("rejects decrypted payloads that do not match stored credential shapes", async () => {
    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const encrypted = await mustAsync(
      encryptSecret(
        encryptionKey,
        JSON.stringify({
          headers: { Authorization: "Bearer secret" },
          oauth: { clientAuthentication: "basic" },
        }),
      ),
    );

    const decrypted = await decryptCredentials(encryptionKey, encrypted);
    expect(decrypted.ok).toBe(false);
    if (!decrypted.ok) {
      expect(decrypted.error.message).toBe("Failed to parse decrypted credentials");
    }
  });

  it("builds headers for each supported auth scheme", () => {
    expect(
      buildCredentialHeaders({ type: "apiKey", in: "header", name: "X-Api-Key" }, "token"),
    ).toEqual({
      "X-Api-Key": "token",
    });
    expect(buildCredentialHeaders({ type: "http", scheme: "basic" }, "user:pass")).toEqual({
      Authorization: "Basic dXNlcjpwYXNz",
    });
    expect(buildCredentialHeaders({ type: "http", scheme: "bearer" }, "token")).toEqual({
      Authorization: "Bearer token",
    });
    expect(
      buildCredentialHeaders(
        {
          type: "oauth2",
          authorizeUrl: "https://example.com/auth",
          tokenUrl: "https://example.com/token",
        },
        "token",
      ),
    ).toEqual({
      Authorization: "Bearer token",
    });
  });
});
