import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const authFlows = wardenSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  service: text('service').notNull(),
  method: text('method').notNull(),
  status: text('status').notNull().default('pending'),
  codeVerifier: text('code_verifier'),
  orgId: text('org_id'),
  oauthSource: text('oauth_source'),
  wardenToken: text('warden_token'),
  identity: text('identity'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
