import { afterEach, describe, expect, it, vi } from "vitest";
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

afterEach(() => {
  vi.restoreAllMocks();
});

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
          revocationUrl: "https://issuer.example.com/revoke",
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
        revocationUrl: "https://issuer.example.com/revoke",
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

  it("surfaces crypto API failures", async () => {
    vi.spyOn(crypto.subtle, "digest").mockRejectedValueOnce(new Error("digest failed"));
    const digestFailure = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY);
    expect(digestFailure.ok).toBe(false);
    if (!digestFailure.ok) {
      expect(digestFailure.error.message).toBe("Failed to derive encryption key");
    }

    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    vi.spyOn(crypto.subtle, "importKey").mockRejectedValueOnce(new Error("import failed"));
    const importFailure = await importAesKey(encryptionKey);
    expect(importFailure.ok).toBe(false);
    if (!importFailure.ok) {
      expect(importFailure.error.message).toBe("Failed to import AES key");
    }

    vi.spyOn(crypto.subtle, "encrypt").mockRejectedValueOnce(new Error("encrypt failed"));
    const encryptFailure = await encryptCredentials(encryptionKey, {
      headers: { Authorization: "Bearer secret" },
    });
    expect(encryptFailure.ok).toBe(false);
    if (!encryptFailure.ok) {
      expect(encryptFailure.error.message).toBe("Failed to encrypt credentials");
    }

    const encrypted = await mustAsync(
      encryptCredentials(encryptionKey, {
        headers: { Authorization: "Bearer secret" },
      }),
    );
    vi.spyOn(crypto.subtle, "decrypt").mockRejectedValueOnce(new Error("decrypt failed"));
    const decryptFailure = await decryptCredentials(encryptionKey, encrypted);
    expect(decryptFailure.ok).toBe(false);
    if (!decryptFailure.ok) {
      expect(decryptFailure.error.message).toBe("Failed to decrypt credentials");
    }
  });

  it("propagates key import failures and parse errors across the remaining helpers", async () => {
    const shortKey = Buffer.from("short").toString("base64");

    const encryptWithShortKey = await encryptCredentials(shortKey, {
      headers: { Authorization: "Bearer secret" },
    });
    expect(encryptWithShortKey.ok).toBe(false);
    if (!encryptWithShortKey.ok) {
      expect(encryptWithShortKey.error.message).toBe("Encryption key must be 32 bytes");
    }

    const encryptedSecretWithShortKey = await encryptSecret(shortKey, "oauth-secret");
    expect(encryptedSecretWithShortKey.ok).toBe(false);
    if (!encryptedSecretWithShortKey.ok) {
      expect(encryptedSecretWithShortKey.error.message).toBe("Encryption key must be 32 bytes");
    }

    const encryptionKey = await mustAsync(deriveEncryptionKey(BISCUIT_PRIVATE_KEY));
    const invalidJson = await mustAsync(encryptSecret(encryptionKey, "{"));
    const parsed = await decryptCredentials(encryptionKey, invalidJson);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.error.message).toBe("Failed to parse decrypted credentials");
    }

    const body = await mustAsync(encryptSecret(encryptionKey, "oauth-secret"));
    const decryptWithShortKey = await decryptCredentials(shortKey, body);
    expect(decryptWithShortKey.ok).toBe(false);
    if (!decryptWithShortKey.ok) {
      expect(decryptWithShortKey.error.message).toBe("Encryption key must be 32 bytes");
    }

    vi.spyOn(crypto.subtle, "encrypt").mockRejectedValueOnce(new Error("encrypt secret failed"));
    const encryptSecretFailure = await encryptSecret(encryptionKey, "oauth-secret");
    expect(encryptSecretFailure.ok).toBe(false);
    if (!encryptSecretFailure.ok) {
      expect(encryptSecretFailure.error.message).toBe("Failed to encrypt secret");
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
