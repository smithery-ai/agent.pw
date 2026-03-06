import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'
import { bytea } from './types'

export const services = wardenSchema.table('services', {
  slug: text('slug').primaryKey(), // unique short ID: github, linear, slack
  allowedHosts: text('allowed_hosts').notNull(), // JSON: string[] of hostnames for SSRF prevention
  displayName: text('display_name'),
  description: text('description'),
  authSchemes: text('auth_schemes'), // JSON: AuthScheme[]
  // Managed OAuth (operational — not part of auth scheme definition)
  oauthClientId: text('oauth_client_id'),
  encryptedOauthClientSecret: bytea('encrypted_oauth_client_secret'),
  docsUrl: text('docs_url'),
  authConfig: text('auth_config'), // JSON: provider-specific overrides
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
