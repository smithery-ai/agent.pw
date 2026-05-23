import { sql } from "drizzle-orm";
import { boolean, index, type pgSchema, primaryKey, timestamp } from "drizzle-orm/pg-core";
import { bytea, jsonb, ltree } from "./types.js";

type PgSchemaNamespace = ReturnType<typeof pgSchema>;

export function defineCredentialsTable(schema: PgSchemaNamespace, tablePrefix = "") {
  const tableName = `${tablePrefix}credentials`;

  return schema.table(
    tableName,
    {
      path: ltree("path").notNull(),
      auth: jsonb<Record<string, unknown>>()("auth").notNull(),
      secret: bytea("secret").notNull(),
      refreshable: boolean("refreshable").default(false).notNull(),
      expiresAt: timestamp("expires_at"),
      refreshCheckedAt: timestamp("refresh_checked_at"),
      createdAt: timestamp("created_at").defaultNow().notNull(),
      updatedAt: timestamp("updated_at").defaultNow().notNull(),
    },
    (table) => [
      primaryKey({
        name: `${tableName}_path_pk`,
        columns: [table.path],
      }),
      index(`${tableName}_path_idx`).using("gist", table.path),
      index(`${tableName}_refresh_due_idx`)
        .on(table.expiresAt)
        .where(sql`${table.refreshable} = true AND ${table.expiresAt} IS NOT NULL`),
      index(`${tableName}_refresh_unknown_idx`)
        .on(table.refreshCheckedAt)
        .where(sql`${table.refreshable} = true AND ${table.expiresAt} IS NULL`),
    ],
  );
}
