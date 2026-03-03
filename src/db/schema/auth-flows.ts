import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const authFlows = wardenSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  service: text('service').notNull(),
  method: text('method').notNull(), // oauth | api_key
  status: text('status').notNull().default('pending'), // pending | completed | expired
  codeVerifier: text('code_verifier'), // PKCE (OAuth only)
  vaultSlug: text('vault_slug'), // which vault to store the credential in
  wardenToken: text('warden_token'), // minted token (set on completion)
  identity: text('identity'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
})
