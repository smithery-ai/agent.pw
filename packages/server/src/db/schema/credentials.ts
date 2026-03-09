import { index, text, timestamp, unique } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { bytea, jsonb } from './types'

export const credentials = agentpwSchema.table('credentials', {
  host: text('host').notNull(),
  slug: text('slug').primaryKey(),
  path: text('path').notNull().default('/'),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  index('credentials_host_idx').on(table.host),
  index('credentials_host_path_idx').on(table.host, table.path),
  unique('credentials_host_path_slug_uniq').on(table.host, table.path, table.slug),
])
