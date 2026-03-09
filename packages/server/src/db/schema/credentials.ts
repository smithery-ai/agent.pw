import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { bytea, jsonb } from './types'

export const credentials = agentpwSchema.table('credentials', {
  host: text('host').notNull(),
  slug: text('slug').primaryKey(),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  execScopes: text('exec_scopes').array().notNull(),
  adminScopes: text('admin_scopes').array().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  index('credentials_host_idx').on(table.host),
  index('credentials_exec_scopes_idx').using('gin', table.execScopes),
  index('credentials_admin_scopes_idx').using('gin', table.adminScopes),
])
