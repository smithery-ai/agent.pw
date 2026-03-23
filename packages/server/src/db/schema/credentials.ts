import { index, type pgSchema, primaryKey, text, timestamp } from 'drizzle-orm/pg-core'
import { bytea, jsonb, ltree } from './types.js'

type PgSchemaNamespace = ReturnType<typeof pgSchema>

export function defineCredentialsTable(
  schema: PgSchemaNamespace,
  tablePrefix = '',
) {
  const tableName = `${tablePrefix}credentials`

  return schema.table(tableName, {
    profilePath: ltree('profile_path').notNull(),
    host: text('host'),
    path: ltree('path').notNull(),
    auth: jsonb<Record<string, unknown>>()('auth').notNull(),
    secret: bytea('secret').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  }, table => [
    primaryKey({
      name: `${tableName}_path_pk`,
      columns: [table.path],
    }),
    index(`${tableName}_host_idx`).on(table.host),
    index(`${tableName}_profile_path_idx`).on(table.profilePath),
    index(`${tableName}_profile_path_path_idx`).on(table.profilePath, table.path),
  ])
}
