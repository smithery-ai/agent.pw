/**
 * Register a managed OAuth app for a service.
 *
 * Usage:
 *   pnpm run managed-oauth <service> <client_id> <client_secret> [scopes]
 *
 * Example:
 *   pnpm run managed-oauth api.github.com Iv1.abc123 s3cret "repo read:user"
 *
 * Requires DATABASE_URL and BISCUIT_PRIVATE_KEY env vars (injected by infisical).
 */

import postgres from 'postgres'
import { deriveEncryptionKey, encryptSecret } from '../src/lib/credentials-crypto'

const [service, clientId, clientSecret, scopes] = process.argv.slice(2)

if (!service || !clientId || !clientSecret) {
  console.error('Usage: managed-oauth <service> <client_id> <client_secret> [scopes]')
  process.exit(1)
}

const databaseUrl = process.env.DATABASE_URL
const biscuitPrivateKey = process.env.BISCUIT_PRIVATE_KEY

if (!databaseUrl) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}
if (!biscuitPrivateKey) {
  console.error('BISCUIT_PRIVATE_KEY is required')
  process.exit(1)
}

const encryptionKey = await deriveEncryptionKey(biscuitPrivateKey)

const sql = postgres(databaseUrl)
const encrypted = await encryptSecret(encryptionKey, clientSecret)

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

if (scopes && row.auth_schemes) {
  const schemes = JSON.parse(row.auth_schemes)
  const oauth = schemes.find((s: Record<string, unknown>) => s.type === 'oauth2')
  if (oauth) {
    oauth.scopes = scopes
    await sql`
      UPDATE warden.services
      SET auth_schemes = ${JSON.stringify(schemes)},
          updated_at = now()
      WHERE service = ${service}
    `
    row.auth_schemes = JSON.stringify(schemes)
  }
}

console.log('Updated managed OAuth for:', service)
console.log('  client_id:', row.oauth_client_id)
console.log('  auth_schemes:', row.auth_schemes)
console.log('  scopes:', scopes ?? '(default)')
console.log('  secret: (encrypted)')

await sql.end()
