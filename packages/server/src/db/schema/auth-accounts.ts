import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'

export const authAccounts = agentpwSchema.table('auth_accounts', {
  id: text('id').primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  providerId: text('provider_id').notNull(),
  accountId: text('account_id').notNull(),
  userId: text('user_id').notNull(),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: timestamp('access_token_expires_at'),
  refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
}, table => [
  index('auth_accounts_user_id_idx').on(table.userId),
  index('auth_accounts_provider_account_idx').on(table.providerId, table.accountId),
])
