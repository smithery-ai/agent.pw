import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'
import { bytea } from './types'

export const services = wardenSchema.table('services', {
  service: text('service').primaryKey(), // hostname: api.github.com
  baseUrl: text('base_url').notNull(),
  displayName: text('display_name'),
  description: text('description'),
  authMethod: text('auth_method').notNull().default('bearer'),
  headerName: text('header_name').notNull().default('Authorization'),
  headerScheme: text('header_scheme').notNull().default('Bearer'),
  // OAuth
  oauthClientId: text('oauth_client_id'),
  encryptedOauthClientSecret: bytea('encrypted_oauth_client_secret'),
  oauthAuthorizeUrl: text('oauth_authorize_url'),
  oauthTokenUrl: text('oauth_token_url'),
  oauthScopes: text('oauth_scopes'),
  // Discovery
  supportedAuthMethods: text('supported_auth_methods'), // JSON: ["oauth","api_key"]
  apiType: text('api_type'), // rest | graphql
  docsUrl: text('docs_url'),
  preview: text('preview'), // JSON
  authConfig: text('auth_config'), // JSON: provider-specific overrides
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
