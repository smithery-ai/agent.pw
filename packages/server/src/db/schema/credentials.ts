import { sql } from "drizzle-orm";
import { index, type pgSchema, primaryKey, timestamp } from "drizzle-orm/pg-core";
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
      oauthAccessTokenExpiresAt: timestamp("oauth_access_token_expires_at"),
      oauthRefreshCheckedAt: timestamp("oauth_refresh_checked_at"),
      createdAt: timestamp("created_at").defaultNow().notNull(),
      updatedAt: timestamp("updated_at").defaultNow().notNull(),
    },
    (table) => [
      primaryKey({
        name: `${tableName}_path_pk`,
        columns: [table.path],
      }),
      index(`${tableName}_path_idx`).using("gist", table.path),
      index(`${tableName}_oauth_refresh_due_idx`)
        .on(table.oauthAccessTokenExpiresAt)
        .where(
          sql`${table.auth}->>'kind' = 'oauth' AND ${table.oauthAccessTokenExpiresAt} IS NOT NULL`,
        ),
      index(`${tableName}_oauth_refresh_unknown_idx`)
        .on(table.oauthRefreshCheckedAt)
        .where(
          sql`${table.auth}->>'kind' = 'oauth' AND ${table.oauthAccessTokenExpiresAt} IS NULL`,
        ),
    ],
  );
}
