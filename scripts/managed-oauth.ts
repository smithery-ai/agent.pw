/**
 * Register a managed OAuth app for a service.
 *
 * Usage:
 *   pnpm run managed-oauth <service> <client_id> <client_secret> [scopes]
 *
 * Example:
 *   pnpm run managed-oauth api.github.com Iv1.abc123 s3cret "repo read:user"
 *
 * Requires DATABASE_URL and ENCRYPTION_KEY env vars (injected by infisical).
 */

import postgres from 'postgres'
import { importAesKey } from '../src/lib/credentials-crypto'

const [service, clientId, clientSecret, scopes] = process.argv.slice(2)

if (!service || !clientId || !clientSecret) {
  console.error('Usage: managed-oauth <service> <client_id> <client_secret> [scopes]')
  process.exit(1)
}

const databaseUrl = process.env.DATABASE_URL
const encryptionKey = process.env.ENCRYPTION_KEY

if (!databaseUrl) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}
if (!encryptionKey) {
  console.error('ENCRYPTION_KEY is required')
  process.exit(1)
}

async function encrypt(key: string, secret: string): Promise<Buffer> {
  const cryptoKey = await importAesKey(key)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(secret)
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext)
  const result = Buffer.alloc(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

const sql = postgres(databaseUrl)
const encrypted = await encrypt(encryptionKey, clientSecret)

await sql`
  UPDATE warden.services
  SET oauth_client_id = ${clientId},
      encrypted_oauth_client_secret = ${encrypted},
      updated_at = now()
  WHERE service = ${service}
`

const [row] = await sql`
  SELECT service, oauth_client_id, auth_schemes
  FROM warden.services
  WHERE service = ${service}
`

if (!row) {
  console.error(`Service '${service}' not found. Register it first via discovery.`)
  await sql.end()
  process.exit(1)
}

console.log('Updated managed OAuth for:', service)
console.log('  client_id:', row.oauth_client_id)
console.log('  auth_schemes:', row.auth_schemes)
console.log('  secret: (encrypted)')

await sql.end()
