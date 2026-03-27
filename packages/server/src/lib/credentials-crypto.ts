import { err, ok, result } from "okay-error";
import type { AuthScheme } from "../auth-schemes.js";
import { cryptoError } from "../errors.js";
import type { OAuthClientAuthenticationMethod } from "../types.js";
import { isRecord } from "./utils.js";

export async function deriveEncryptionKey(secretSeed: string) {
  const input = new TextEncoder().encode(`${secretSeed}:credential-encryption`);
  const hash = await result(crypto.subtle.digest("SHA-256", input));
  if (!hash.ok) {
    return err(
      cryptoError("deriveEncryptionKey", "Failed to derive encryption key", {
        cause: hash.error,
      }),
    );
  }
  return ok(Buffer.from(hash.value).toString("base64"));
}

export interface StoredHeadersCredentials {
  headers: Record<string, string>;
  env?: never;
  oauth?: never;
}

export interface StoredEnvCredentials {
  headers?: never;
  env: Record<string, string>;
  oauth?: never;
}

export interface StoredOAuthCredentials {
  headers: Record<string, string>;
  env?: never;
  oauth: {
    refreshToken?: string | null;
    accessToken?: string | null;
    expiresAt?: string;
    scopes?: string;
    tokenType?: string;
    resource?: string;
    issuer?: string;
    authorizationUrl?: string;
    tokenUrl?: string;
    revocationUrl?: string;
    clientId?: string;
    clientSecret?: string;
    clientAuthentication?: OAuthClientAuthenticationMethod;
  };
}

export type StoredCredentials =
  | StoredHeadersCredentials
  | StoredEnvCredentials
  | StoredOAuthCredentials;

const STORED_CREDENTIAL_KEYS = new Set(["env", "headers", "oauth"]);
const STORED_OAUTH_KEYS = new Set([
  "accessToken",
  "authorizationUrl",
  "clientAuthentication",
  "clientId",
  "clientSecret",
  "expiresAt",
  "issuer",
  "refreshToken",
  "resource",
  "revocationUrl",
  "scopes",
  "tokenType",
  "tokenUrl",
]);

function hasOnlyKeys(value: Record<string, unknown>, keys: Set<string>) {
  return Object.keys(value).every((key) => keys.has(key));
}

function isStringMap(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.values(value).every((entry) => typeof entry === "string");
}

function isStoredOAuth(value: unknown): value is StoredOAuthCredentials["oauth"] {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, STORED_OAUTH_KEYS) &&
    (value.refreshToken === undefined ||
      value.refreshToken === null ||
      typeof value.refreshToken === "string") &&
    (value.accessToken === undefined ||
      value.accessToken === null ||
      typeof value.accessToken === "string") &&
    (value.expiresAt === undefined || typeof value.expiresAt === "string") &&
    (value.scopes === undefined || typeof value.scopes === "string") &&
    (value.tokenType === undefined || typeof value.tokenType === "string") &&
    (value.resource === undefined || typeof value.resource === "string") &&
    (value.issuer === undefined || typeof value.issuer === "string") &&
    (value.authorizationUrl === undefined || typeof value.authorizationUrl === "string") &&
    (value.tokenUrl === undefined || typeof value.tokenUrl === "string") &&
    (value.revocationUrl === undefined || typeof value.revocationUrl === "string") &&
    (value.clientId === undefined || typeof value.clientId === "string") &&
    (value.clientSecret === undefined || typeof value.clientSecret === "string") &&
    (value.clientAuthentication === undefined ||
      value.clientAuthentication === "client_secret_basic" ||
      value.clientAuthentication === "client_secret_post" ||
      value.clientAuthentication === "none")
  );
}

function isStoredCredentials(value: unknown): value is StoredCredentials {
  if (!isRecord(value) || !hasOnlyKeys(value, STORED_CREDENTIAL_KEYS)) {
    return false;
  }
  if ("env" in value) {
    return !("headers" in value) && !("oauth" in value) && isStringMap(value.env);
  }
  if ("oauth" in value) {
    return "headers" in value && isStringMap(value.headers) && isStoredOAuth(value.oauth);
  }
  return "headers" in value && isStringMap(value.headers);
}

export async function importAesKey(encryptionKey: string) {
  const raw = new Uint8Array(Buffer.from(encryptionKey, "base64"));
  if (raw.length !== 32) {
    return err(cryptoError("importAesKey", "Encryption key must be 32 bytes"));
  }

  const key = await result(
    crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]),
  );
  if (!key.ok) {
    return err(
      cryptoError("importAesKey", "Failed to import AES key", {
        cause: key.error,
      }),
    );
  }

  return key;
}

export async function encryptCredentials(encryptionKey: string, credentials: StoredCredentials) {
  const key = await importAesKey(encryptionKey);
  if (!key.ok) {
    return key;
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));
  const ciphertext = await result(
    crypto.subtle.encrypt({ name: "AES-GCM", iv }, key.value, plaintext),
  );
  if (!ciphertext.ok) {
    return err(
      cryptoError("encryptCredentials", "Failed to encrypt credentials", {
        cause: ciphertext.error,
      }),
    );
  }

  const output = Buffer.alloc(12 + ciphertext.value.byteLength);
  output.set(iv, 0);
  output.set(new Uint8Array(ciphertext.value), 12);
  return ok(output);
}

export async function decryptCredentials(encryptionKey: string, encrypted: Buffer) {
  if (encrypted.length < 12 + 16) {
    return err(cryptoError("decryptCredentials", "Invalid ciphertext"));
  }

  const key = await importAesKey(encryptionKey);
  if (!key.ok) {
    return key;
  }

  const iv = new Uint8Array(encrypted.subarray(0, 12));
  const ciphertext = new Uint8Array(encrypted.subarray(12));
  const plaintext = await result(
    crypto.subtle.decrypt({ name: "AES-GCM", iv }, key.value, ciphertext),
  );
  if (!plaintext.ok) {
    return err(
      cryptoError("decryptCredentials", "Failed to decrypt credentials", {
        cause: plaintext.error,
      }),
    );
  }

  const decoded = result(() => JSON.parse(new TextDecoder().decode(plaintext.value)));
  if (!decoded.ok) {
    return err(
      cryptoError("decryptCredentials", "Failed to parse decrypted credentials", {
        cause: decoded.error,
      }),
    );
  }

  if (!isStoredCredentials(decoded.value)) {
    return err(cryptoError("decryptCredentials", "Failed to parse decrypted credentials"));
  }

  return ok(decoded.value);
}

export function buildCredentialHeaders(scheme: AuthScheme, token: string): Record<string, string> {
  switch (scheme.type) {
    case "apiKey":
      return { [scheme.name]: token };
    case "http":
      if (scheme.scheme === "basic") {
        return { Authorization: `Basic ${btoa(token)}` };
      }
      return { Authorization: `Bearer ${token}` };
    case "oauth2":
      return { Authorization: `Bearer ${token}` };
  }
}

export async function encryptSecret(encryptionKey: string, secret: string) {
  const key = await importAesKey(encryptionKey);
  if (!key.ok) {
    return key;
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(secret);
  const ciphertext = await result(
    crypto.subtle.encrypt({ name: "AES-GCM", iv }, key.value, plaintext),
  );
  if (!ciphertext.ok) {
    return err(
      cryptoError("encryptSecret", "Failed to encrypt secret", {
        cause: ciphertext.error,
      }),
    );
  }

  const output = Buffer.alloc(12 + ciphertext.value.byteLength);
  output.set(iv, 0);
  output.set(new Uint8Array(ciphertext.value), 12);
  return ok(output);
}
