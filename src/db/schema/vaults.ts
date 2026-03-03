import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const vaults = wardenSchema.table('vaults', {
  slug: text('slug').primaryKey(),
  displayName: text('display_name'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
