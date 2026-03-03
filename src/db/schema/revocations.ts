import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const revocations = wardenSchema.table('revocations', {
  revocationId: text('revocation_id').primaryKey(),
  revokedAt: timestamp('revoked_at').defaultNow().notNull(),
  reason: text('reason'),
})
