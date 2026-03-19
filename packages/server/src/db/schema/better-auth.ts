import {
  boolean,
  index,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { jsonb } from './types.js'

export const authUsers = agentpwSchema.table('auth_user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull(),
  emailVerified: boolean('email_verified').notNull().default(false),
  image: text('image'),
  orgId: text('org_id'),
  workosUserId: text('workos_user_id'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, table => ({
  emailUniqueIdx: uniqueIndex('auth_user_email_unique').on(table.email),
  orgIdx: index('auth_user_org_idx').on(table.orgId),
  workosUserIdx: uniqueIndex('auth_user_workos_user_id_unique').on(table.workosUserId),
}))

export const authSessions = agentpwSchema.table('auth_session', {
  id: text('id').primaryKey(),
  expiresAt: timestamp('expires_at').notNull(),
  token: text('token').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id').notNull().references(() => authUsers.id, { onDelete: 'cascade' }),
}, table => ({
  tokenUniqueIdx: uniqueIndex('auth_session_token_unique').on(table.token),
  userIdx: index('auth_session_user_idx').on(table.userId),
}))

export const authAccounts = agentpwSchema.table('auth_account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull().references(() => authUsers.id, { onDelete: 'cascade' }),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, table => ({
  providerAccountUniqueIdx: uniqueIndex('auth_account_provider_account_unique')
    .on(table.providerId, table.accountId),
  userIdx: index('auth_account_user_idx').on(table.userId),
}))

export const authVerifications = agentpwSchema.table('auth_verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, table => ({
  identifierIdx: index('auth_verification_identifier_idx').on(table.identifier),
}))

export const authJwks = agentpwSchema.table('auth_jwks', {
  id: text('id').primaryKey(),
  publicKey: text('public_key').notNull(),
  privateKey: text('private_key').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at'),
})

export const authOauthClients = agentpwSchema.table('auth_oauth_client', {
  id: text('id').primaryKey(),
  clientId: text('client_id').notNull(),
  clientSecret: text('client_secret'),
  disabled: boolean('disabled').default(false),
  skipConsent: boolean('skip_consent'),
  enableEndSession: boolean('enable_end_session'),
  subjectType: text('subject_type'),
  scopes: text('scopes').array(),
  userId: text('user_id').references(() => authUsers.id),
  referenceId: text('reference_id'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
  name: text('name'),
  uri: text('uri'),
  icon: text('icon'),
  contacts: text('contacts').array(),
  tos: text('tos'),
  policy: text('policy'),
  softwareId: text('software_id'),
  softwareVersion: text('software_version'),
  softwareStatement: text('software_statement'),
  redirectUris: text('redirect_uris').array().notNull(),
  postLogoutRedirectUris: text('post_logout_redirect_uris').array(),
  tokenEndpointAuthMethod: text('token_endpoint_auth_method'),
  grantTypes: text('grant_types').array(),
  responseTypes: text('response_types').array(),
  public: boolean('public'),
  type: text('type'),
  requirePKCE: boolean('require_pkce'),
  metadata: jsonb<Record<string, unknown>>()('metadata'),
}, table => ({
  clientIdUniqueIdx: uniqueIndex('auth_oauth_client_client_id_unique').on(table.clientId),
  userIdx: index('auth_oauth_client_user_idx').on(table.userId),
  referenceIdx: index('auth_oauth_client_reference_idx').on(table.referenceId),
}))

export const authOauthRefreshTokens = agentpwSchema.table('auth_oauth_refresh_token', {
  id: text('id').primaryKey(),
  token: text('token').notNull(),
  clientId: text('client_id').notNull().references(() => authOauthClients.clientId),
  sessionId: text('session_id').references(() => authSessions.id, { onDelete: 'set null' }),
  userId: text('user_id').notNull().references(() => authUsers.id),
  referenceId: text('reference_id'),
  scopes: text('scopes').array().notNull(),
  revoked: timestamp('revoked'),
  authTime: timestamp('auth_time'),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at'),
}, table => ({
  tokenUniqueIdx: uniqueIndex('auth_oauth_refresh_token_token_unique').on(table.token),
  clientIdx: index('auth_oauth_refresh_token_client_idx').on(table.clientId),
  userIdx: index('auth_oauth_refresh_token_user_idx').on(table.userId),
}))

export const authOauthAccessTokens = agentpwSchema.table('auth_oauth_access_token', {
  id: text('id').primaryKey(),
  token: text('token').notNull(),
  clientId: text('client_id').notNull().references(() => authOauthClients.clientId),
  sessionId: text('session_id').references(() => authSessions.id, { onDelete: 'set null' }),
  userId: text('user_id').references(() => authUsers.id),
  referenceId: text('reference_id'),
  refreshId: text('refresh_id').references(() => authOauthRefreshTokens.id),
  scopes: text('scopes').array().notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at'),
}, table => ({
  tokenUniqueIdx: uniqueIndex('auth_oauth_access_token_token_unique').on(table.token),
  clientIdx: index('auth_oauth_access_token_client_idx').on(table.clientId),
  userIdx: index('auth_oauth_access_token_user_idx').on(table.userId),
}))

export const authOauthConsents = agentpwSchema.table('auth_oauth_consent', {
  id: text('id').primaryKey(),
  clientId: text('client_id').notNull().references(() => authOauthClients.clientId),
  userId: text('user_id').references(() => authUsers.id),
  referenceId: text('reference_id'),
  scopes: text('scopes').array().notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
}, table => ({
  clientIdx: index('auth_oauth_consent_client_idx').on(table.clientId),
  userIdx: index('auth_oauth_consent_user_idx').on(table.userId),
}))
