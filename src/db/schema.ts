import { pgSchema, text, timestamp, primaryKey, integer } from 'drizzle-orm/pg-core'

export const wardenSchema = pgSchema('warden')

export const vaults = wardenSchema.table('vaults', {
  slug: text('slug').primaryKey(),
  displayName: text('display_name'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})

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
  oauthClientSecret: text('oauth_client_secret'),
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

export const credentials = wardenSchema.table(
  'credentials',
  {
    vaultSlug: text('vault_slug').notNull(),
    service: text('service').notNull(),
    identity: text('identity'), // informational — resolved via whoami
    token: text('token').notNull(),
    metadata: text('metadata'), // JSON
    expiresAt: timestamp('expires_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  t => [primaryKey({ columns: [t.vaultSlug, t.service] })],
)

export const revocations = wardenSchema.table('revocations', {
  revocationId: text('revocation_id').primaryKey(),
  revokedAt: timestamp('revoked_at').defaultNow().notNull(),
  reason: text('reason'),
})

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

export const docPages = wardenSchema.table(
  'doc_pages',
  {
    hostname: text('hostname').notNull(),
    path: text('path').notNull(),
    content: text('content'),
    status: text('status').notNull().default('skeleton'),
    generatedAt: timestamp('generated_at').defaultNow().notNull(),
    ttlDays: integer('ttl_days').notNull().default(7),
  },
  t => [primaryKey({ columns: [t.hostname, t.path] })],
)
