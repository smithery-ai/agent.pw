import { index, type pgSchema, primaryKey, text, timestamp } from 'drizzle-orm/pg-core'
import { bytea, jsonb, ltree } from './types.js'

type PgSchemaNamespace = ReturnType<typeof pgSchema>

export function defineCredentialsTable(
  schema: PgSchemaNamespace,
  tablePrefix = '',
) {
  const tableName = `${tablePrefix}credentials`

  return schema.table(tableName, {
    path: ltree('path').notNull(),
    resource: text('resource').notNull(),
    auth: jsonb<Record<string, unknown>>()('auth').notNull(),
    secret: bytea('secret').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  }, table => [
    primaryKey({
      name: `${tableName}_path_pk`,
      columns: [table.path],
    }),
    index(`${tableName}_resource_idx`).on(table.resource),
  ])
}
