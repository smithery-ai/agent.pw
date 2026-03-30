import { err, ok } from "okay-error";
import { sql } from "drizzle-orm";
import { inputError } from "../errors.js";
import { isRecord } from "../lib/utils.js";
import type { SqlNamespaceOptions } from "../types.js";
import type { Database } from "./index";
import { coerceSqlNamespace, type AgentPwSqlNamespace } from "./schema/index.js";

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace;

function quoteIdentifier(identifier: string) {
  return `"${identifier}"`;
}

function qualifyTable(schema: string, tableName: string) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(tableName)}`;
}

function resultRows(result: unknown) {
  if (Array.isArray(result)) {
    return result;
  }

  if (isRecord(result) && Array.isArray(result.rows)) {
    return result.rows;
  }

  return [];
}

function rowUdtName(row: unknown) {
  if (!isRecord(row) || typeof row.udt_name !== "string") {
    return undefined;
  }

  return row.udt_name;
}

async function ensureLtreePathColumn(
  db: Database,
  schemaName: string,
  tableName: string,
  tableLabel: string,
) {
  const result = await db.execute(sql`
    SELECT udt_name
    FROM information_schema.columns
    WHERE table_schema = ${schemaName}
      AND table_name = ${tableName}
      AND column_name = 'path'
  `);
  const udtName = rowUdtName(resultRows(result)[0]);
  if (!udtName || udtName === "ltree") {
    return ok();
  }

  return err(
    inputError(
      `${tableLabel} path column must use ltree; recreate or migrate the local database before bootstrapping`,
    ),
  );
}

/** Bootstrap the local PGlite schema without relying on framework-owned migration files. */
export async function bootstrapLocalSchema(
  db: Database,
  options: {
    sql?: SqlNamespaceInput;
  } = {},
) {
  const sqlNamespace = coerceSqlNamespace(options.sql);
  if (!sqlNamespace.ok) {
    return sqlNamespace;
  }
  const schemaName = sqlNamespace.value.schema;
  const credProfilesTable = sqlNamespace.value.tableName("cred_profiles");
  const credentialsTable = sqlNamespace.value.tableName("credentials");
  const credProfilesPathIndex = `${credProfilesTable}_path_idx`;
  const credProfilesResourcePatternsIndex = `${credProfilesTable}_resource_patterns_idx`;
  const credentialsPathIndex = `${credentialsTable}_path_idx`;
  const credentialsPathPrimaryKey = `${credentialsTable}_path_pk`;
  const schemaSql = quoteIdentifier(schemaName);
  const credProfilesSql = qualifyTable(schemaName, credProfilesTable);
  const credentialsSql = qualifyTable(schemaName, credentialsTable);

  await db.execute(sql.raw("CREATE EXTENSION IF NOT EXISTS ltree"));
  await db.execute(sql.raw(`CREATE SCHEMA IF NOT EXISTS ${schemaSql}`));

  const credProfilesPath = await ensureLtreePathColumn(
    db,
    schemaName,
    credProfilesTable,
    "Credential profile",
  );
  if (!credProfilesPath.ok) {
    return credProfilesPath;
  }

  const credentialsPath = await ensureLtreePathColumn(
    db,
    schemaName,
    credentialsTable,
    "Credential",
  );
  if (!credentialsPath.ok) {
    return credentialsPath;
  }

  await db.execute(
    sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credProfilesSql} (
      path LTREE PRIMARY KEY,
      resource_patterns JSONB NOT NULL DEFAULT '[]'::jsonb,
      auth JSONB NOT NULL DEFAULT '{}'::jsonb,
      display_name TEXT,
      description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `),
  );

  await db.execute(
    sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesPathIndex)}
    ON ${credProfilesSql} USING gist (path)
  `),
  );

  await db.execute(
    sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesResourcePatternsIndex)}
    ON ${credProfilesSql} USING gin (resource_patterns)
  `),
  );

  await db.execute(
    sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credentialsSql} (
      path LTREE NOT NULL,
      auth JSONB NOT NULL,
      secret BYTEA NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      CONSTRAINT ${quoteIdentifier(credentialsPathPrimaryKey)} PRIMARY KEY (path)
    )
  `),
  );

  await db.execute(
    sql.raw(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = '${schemaName}'
          AND table_name = '${credentialsTable}'
          AND column_name = 'resource'
      ) THEN
        UPDATE ${credentialsSql}
        SET auth = jsonb_set(auth, '{resource}', to_jsonb(resource), true)
        WHERE coalesce(resource, '') <> ''
          AND coalesce(auth->>'resource', '') = ''
          AND coalesce(auth->>'kind', '') IN ('oauth', 'headers');

        DROP INDEX IF EXISTS ${quoteIdentifier(`${credentialsTable}_resource_idx`)};
        ALTER TABLE ${credentialsSql} DROP COLUMN resource;
      END IF;
    END $$;
  `),
  );

  await db.execute(
    sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credentialsPathIndex)}
    ON ${credentialsSql} USING gist (path)
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "auth_flows")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "verification")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "auth_accounts")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "auth_sessions")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "auth_users")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "auth_verifications")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "issued_tokens")}
  `),
  );

  await db.execute(
    sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, "revocations")}
  `),
  );

  return ok();
}
