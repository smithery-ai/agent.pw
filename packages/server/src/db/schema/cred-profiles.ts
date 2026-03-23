import { index, type pgSchema, text, timestamp } from 'drizzle-orm/pg-core'
import { jsonb, ltree } from './types.js'

type PgSchemaNamespace = ReturnType<typeof pgSchema>

export function defineCredProfilesTable(
  schema: PgSchemaNamespace,
  tablePrefix = '',
) {
  const tableName = `${tablePrefix}cred_profiles`

  return schema.table(tableName, {
    path: ltree('path').primaryKey(),
    host: jsonb<string[]>()('host').notNull(),
    auth: jsonb<Record<string, unknown>>()('auth'),
    oauthConfig: jsonb<Record<string, unknown>>()('oauth_config'),
    displayName: text('display_name'),
    description: text('description'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  }, table => [
    index(`${tableName}_path_idx`).on(table.path),
    index(`${tableName}_host_idx`).using('gin', table.host),
  ])
}
