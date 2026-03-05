/**
 * Re-encrypt all encrypted data from old ENCRYPTION_KEY to derived key.
 *
 * Usage:
 *   DATABASE_URL=... ENCRYPTION_KEY=... BISCUIT_PRIVATE_KEY=... bun scripts/reencrypt.ts
 *
 * Reads with old ENCRYPTION_KEY, writes with deriveEncryptionKey(BISCUIT_PRIVATE_KEY).
 * Run this once, then delete ENCRYPTION_KEY from Infisical.
 */

import postgres from 'postgres'
import { importAesKey, deriveEncryptionKey } from '../src/lib/credentials-crypto'

const databaseUrl = process.env.DATABASE_URL
const oldKey = process.env.ENCRYPTION_KEY
const biscuitPrivateKey = process.env.BISCUIT_PRIVATE_KEY

if (!databaseUrl || !oldKey || !biscuitPrivateKey) {
  console.error('Required: DATABASE_URL, ENCRYPTION_KEY (old), BISCUIT_PRIVATE_KEY')
  process.exit(1)
}

const newKey = await deriveEncryptionKey(biscuitPrivateKey)

async function decrypt(key: string, encrypted: Buffer): Promise<Buffer> {
  const cryptoKey = await importAesKey(key)
  const iv = new Uint8Array(encrypted.subarray(0, 12))
  const ciphertext = new Uint8Array(encrypted.subarray(12))
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertext)
  return Buffer.from(plaintext)
}

async function encrypt(key: string, plaintext: Buffer): Promise<Buffer> {
  const cryptoKey = await importAesKey(key)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext)
  const result = Buffer.alloc(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

async function reencrypt(data: Buffer): Promise<Buffer> {
  const plaintext = await decrypt(oldKey, data)
  return encrypt(newKey, plaintext)
}

const sql = postgres(databaseUrl)

// 1. credentials.encrypted_credentials
const creds = await sql`SELECT org_id, service, slug, encrypted_credentials FROM warden.credentials`
console.log(`Credentials: ${creds.length} rows`)
for (const row of creds) {
  const updated = await reencrypt(row.encrypted_credentials)
  await sql`UPDATE warden.credentials SET encrypted_credentials = ${updated} WHERE org_id = ${row.org_id} AND service = ${row.service} AND slug = ${row.slug}`
}

// 2. services.encrypted_oauth_client_secret
const svcs = await sql`SELECT service, encrypted_oauth_client_secret FROM warden.services WHERE encrypted_oauth_client_secret IS NOT NULL`
console.log(`Services with OAuth secrets: ${svcs.length} rows`)
for (const row of svcs) {
  const updated = await reencrypt(row.encrypted_oauth_client_secret)
  await sql`UPDATE warden.services SET encrypted_oauth_client_secret = ${updated} WHERE service = ${row.service}`
}

console.log('Done. You can now remove ENCRYPTION_KEY from Infisical.')
await sql.end()
