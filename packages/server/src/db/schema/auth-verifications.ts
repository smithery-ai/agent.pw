import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'

export const authVerifications = agentpwSchema.table('auth_verifications', {
  id: text('id').primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  value: text('value').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  identifier: text('identifier').notNull(),
}, table => [
  index('auth_verifications_identifier_idx').on(table.identifier),
])
