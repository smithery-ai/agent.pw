import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { bytea, jsonb } from './types'

export const credentials = agentpwSchema.table('credentials', {
  id: text('id').primaryKey(),
  host: text('host').notNull(),
  slug: text('slug').notNull().unique(),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  execPolicy: text('exec_policy'),
  adminPolicy: text('admin_policy'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
