import { index, type pgSchema, text, timestamp } from "drizzle-orm/pg-core";
import { jsonb, ltree } from "./types.js";

type PgSchemaNamespace = ReturnType<typeof pgSchema>;

export function defineCredProfilesTable(schema: PgSchemaNamespace, tablePrefix = "") {
  const tableName = `${tablePrefix}cred_profiles`;

  return schema.table(
    tableName,
    {
      path: ltree("path").primaryKey(),
      resourcePatterns: jsonb<string[]>()("resource_patterns").notNull(),
      auth: jsonb<Record<string, unknown>>()("auth").notNull(),
      displayName: text("display_name"),
      description: text("description"),
      createdAt: timestamp("created_at").defaultNow().notNull(),
      updatedAt: timestamp("updated_at").defaultNow().notNull(),
    },
    (table) => [
      index(`${tableName}_path_idx`).using("gist", table.path),
      index(`${tableName}_resource_patterns_idx`).using("gin", table.resourcePatterns),
    ],
  );
}
