import type { AuthScheme } from '../auth-schemes'

/**
 * Credentials stored alongside a connection, encrypted at rest in the database.
 * Used by the proxy to inject auth headers when forwarding to upstream APIs.
 */
export type StoredCredentials = {
  headers: Record<string, string>
  oauth?: {
    refreshToken: string
    accessToken: string
    expiresAt?: string
    tokenUrl: string
    clientId: string
    clientSecret?: string
    scopes?: string
  }
}

/**
 * Import a base64-encoded AES-256 key for use with crypto.subtle.
 */
export async function importAesKey(encryptionKey: string): Promise<CryptoKey> {
  const raw = new Uint8Array(Buffer.from(encryptionKey, 'base64'))
  if (raw.length !== 32) throw new Error('Encryption key must be 32 bytes')
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/**
 * Encrypt credentials to raw bytes for DB storage (bytea column).
 * Format: [12-byte IV][ciphertext + 16-byte GCM tag]
 */
export async function encryptCredentials(
  encryptionKey: string,
  credentials: StoredCredentials,
): Promise<Buffer> {
  const key = await importAesKey(encryptionKey)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  const result = Buffer.alloc(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

/**
 * Decrypt credentials from raw bytes stored in DB.
 */
export async function decryptCredentials(
  encryptionKey: string,
  encrypted: Buffer,
): Promise<StoredCredentials> {
  if (encrypted.length < 12 + 16) throw new Error('Invalid ciphertext')
  const key = await importAesKey(encryptionKey)
  const iv = new Uint8Array(encrypted.subarray(0, 12))
  const ciphertext = new Uint8Array(encrypted.subarray(12))
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  return JSON.parse(new TextDecoder().decode(plaintext))
}

/**
 * Derive proxy headers from a token and an auth scheme.
 * Each scheme type is self-describing — no ambiguity about formatting.
 */
export function buildCredentialHeaders(
  scheme: AuthScheme,
  token: string,
): Record<string, string> {
  switch (scheme.type) {
    case 'apiKey':
      return { [scheme.name]: token }
    case 'http':
      if (scheme.scheme === 'basic') return { Authorization: `Basic ${btoa(token)}` }
      return { Authorization: `Bearer ${token}` }
    case 'oauth2':
      return { Authorization: `Bearer ${token}` }
  }
}
