import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'
import { bytea } from './types'

export const services = wardenSchema.table('services', {
  service: text('service').primaryKey(), // hostname: api.github.com
  baseUrl: text('base_url').notNull(),
  displayName: text('display_name'),
  description: text('description'),
  authSchemes: text('auth_schemes'), // JSON: AuthScheme[]
  // Managed OAuth (operational — not part of auth scheme definition)
  oauthClientId: text('oauth_client_id'),
  encryptedOauthClientSecret: bytea('encrypted_oauth_client_secret'),
  // Discovery
  apiType: text('api_type'), // rest | graphql
  docsUrl: text('docs_url'),
  preview: text('preview'), // JSON
  authConfig: text('auth_config'), // JSON: provider-specific overrides
  // Webhooks
  webhookConfig: text('webhook_config'), // JSON: WebhookConfig for signature verification
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
