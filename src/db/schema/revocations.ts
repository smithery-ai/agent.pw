import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'

export const revocations = agentpwSchema.table('revocations', {
  revocationId: text('revocation_id').primaryKey(),
  revokedAt: timestamp('revoked_at').defaultNow().notNull(),
  reason: text('reason'),
})
