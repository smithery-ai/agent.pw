import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { jsonb } from './types'

export const credProfiles = agentpwSchema.table('cred_profiles', {
  slug: text('slug').primaryKey(),
  host: jsonb<string[]>()('host').notNull(),
  path: text('path').notNull().default('/'),
  auth: jsonb<Record<string, unknown>>()('auth'),
  managedOauth: jsonb<Record<string, unknown>>()('managed_oauth'),
  displayName: text('display_name'),
  description: text('description'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
