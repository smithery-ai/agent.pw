import { describe, expect, it } from 'vitest'
import {
  buildCredentialHeaders,
  decryptCredentials,
  deriveEncryptionKey,
  encryptCredentials,
  encryptSecret,
  importAesKey,
} from '@agent.pw/server/crypto'
import { BISCUIT_PRIVATE_KEY } from './setup'

async function decryptSecretBuffer(encryptionKey: string, encrypted: Buffer) {
  const key = await importAesKey(encryptionKey)
  const iv = encrypted.subarray(0, 12)
  const ciphertext = encrypted.subarray(12)
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  return new TextDecoder().decode(plaintext)
}

describe('credentials crypto', () => {
  it('derives deterministic AES keys from the biscuit private key', async () => {
    const first = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const second = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const other = await deriveEncryptionKey('ed25519-private/another-secret')

    expect(first).toBe(second)
    expect(first).not.toBe(other)
    expect(Buffer.from(first, 'base64')).toHaveLength(32)
  })

  it('encrypts and decrypts structured credentials', async () => {
    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const encrypted = await encryptCredentials(encryptionKey, {
      headers: { Authorization: 'Bearer secret' },
      oauth: {
        accessToken: 'access',
        refreshToken: 'refresh',
        tokenUrl: 'https://example.com/token',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        scopes: 'repo',
      },
    })

    expect(await decryptCredentials(encryptionKey, encrypted)).toEqual({
      headers: { Authorization: 'Bearer secret' },
      oauth: {
        accessToken: 'access',
        refreshToken: 'refresh',
        tokenUrl: 'https://example.com/token',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        scopes: 'repo',
      },
    })
  })

  it('rejects invalid encryption inputs and can encrypt standalone secrets', async () => {
    await expect(importAesKey(Buffer.from('short').toString('base64'))).rejects.toThrow('Encryption key must be 32 bytes')

    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    await expect(decryptCredentials(encryptionKey, Buffer.alloc(8))).rejects.toThrow('Invalid ciphertext')

    const encryptedSecret = await encryptSecret(encryptionKey, 'oauth-secret')
    expect(await decryptSecretBuffer(encryptionKey, encryptedSecret)).toBe('oauth-secret')
  })

  it('builds headers for each supported auth scheme', () => {
    expect(buildCredentialHeaders({ type: 'apiKey', in: 'header', name: 'X-Api-Key' }, 'token')).toEqual({
      'X-Api-Key': 'token',
    })
    expect(buildCredentialHeaders({ type: 'http', scheme: 'basic' }, 'user:pass')).toEqual({
      Authorization: 'Basic dXNlcjpwYXNz',
    })
    expect(buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, 'token')).toEqual({
      Authorization: 'Bearer token',
    })
    expect(buildCredentialHeaders({
      type: 'oauth2',
      authorizeUrl: 'https://example.com/auth',
      tokenUrl: 'https://example.com/token',
    }, 'token')).toEqual({
      Authorization: 'Bearer token',
    })
  })
})
