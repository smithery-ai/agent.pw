import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const authFlows = wardenSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  slug: text('slug').notNull(), // service slug
  method: text('method').notNull(),
  status: text('status').notNull().default('pending'),
  codeVerifier: text('code_verifier'),
  orgId: text('org_id'),
  token: text('token'),
  identity: text('identity'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
