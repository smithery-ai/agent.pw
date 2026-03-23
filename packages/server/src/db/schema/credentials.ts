import { index, primaryKey, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { bytea, jsonb, ltree } from './types.js'

export const credentials = agentpwSchema.table('credentials', {
  profilePath: ltree('profile_path').notNull(),
  host: text('host'),
  path: ltree('path').notNull(),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  primaryKey({
    name: 'credentials_path_pk',
    columns: [table.path],
  }),
  index('credentials_host_idx').on(table.host),
  index('credentials_profile_path_idx').on(table.profilePath),
  index('credentials_profile_path_path_idx').on(table.profilePath, table.path),
])
