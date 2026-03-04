import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const users = wardenSchema.table('users', {
  workosUserId: text('workos_user_id').primaryKey(),
  workosOrgId: text('workos_org_id').notNull(),
  email: text('email'),
  name: text('name'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
