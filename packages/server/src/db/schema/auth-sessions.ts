import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'

export const authSessions = agentpwSchema.table('auth_sessions', {
  id: text('id').primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  userId: text('user_id').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  token: text('token').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
}, table => [
  index('auth_sessions_user_id_idx').on(table.userId),
  index('auth_sessions_token_idx').on(table.token),
])
