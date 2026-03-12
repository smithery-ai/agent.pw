import { index, primaryKey, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { bytea, jsonb, ltree } from './types.js'

export const credentials = agentpwSchema.table('credentials', {
  host: text('host').notNull(),
  path: ltree('path').notNull(),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  primaryKey({
    name: 'credentials_host_path_pk',
    columns: [table.host, table.path],
  }),
  index('credentials_host_idx').on(table.host),
  index('credentials_host_path_idx').on(table.host, table.path),
])
