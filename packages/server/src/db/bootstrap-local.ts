import { sql } from 'drizzle-orm'
import type { SqlNamespaceOptions } from '../types.js'
import type { Database } from './index'
import { coerceSqlNamespace, type AgentPwSqlNamespace } from './schema/index.js'

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace

function quoteIdentifier(identifier: string) {
  return `"${identifier}"`
}

function qualifyTable(schema: string, tableName: string) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(tableName)}`
}

/** Bootstrap the local PGlite schema without relying on checked-in Drizzle migrations. */
export async function bootstrapLocalSchema(
  db: Database,
  options: {
    sql?: SqlNamespaceInput
  } = {},
) {
  const sqlNamespace = coerceSqlNamespace(options.sql)
  const schemaName = sqlNamespace.schema
  const credProfilesTable = sqlNamespace.tableName('cred_profiles')
  const credentialsTable = sqlNamespace.tableName('credentials')
  const credProfilesPathIndex = `${credProfilesTable}_path_idx`
  const credProfilesResourcePatternsIndex = `${credProfilesTable}_resource_patterns_idx`
  const credentialsResourceIndex = `${credentialsTable}_resource_idx`
  const credentialsPathPrimaryKey = `${credentialsTable}_path_pk`
  const schemaSql = quoteIdentifier(schemaName)
  const credProfilesSql = qualifyTable(schemaName, credProfilesTable)
  const credentialsSql = qualifyTable(schemaName, credentialsTable)

  await db.execute(sql.raw(`CREATE SCHEMA IF NOT EXISTS ${schemaSql}`))

  await db.execute(sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credProfilesSql} (
      path TEXT PRIMARY KEY,
      resource_patterns JSONB NOT NULL DEFAULT '[]'::jsonb,
      auth JSONB NOT NULL DEFAULT '{}'::jsonb,
      display_name TEXT,
      description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesPathIndex)}
    ON ${credProfilesSql} (path)
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesResourcePatternsIndex)}
    ON ${credProfilesSql} USING gin (resource_patterns)
  `))

  await db.execute(sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credentialsSql} (
      path TEXT NOT NULL,
      resource TEXT NOT NULL DEFAULT '',
      auth JSONB NOT NULL,
      secret BYTEA NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now(),
      CONSTRAINT ${quoteIdentifier(credentialsPathPrimaryKey)} PRIMARY KEY (path)
    )
  `))

  await db.execute(sql.raw(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = '${schemaName}'
          AND table_name = '${credentialsTable}'
          AND column_name = 'resource'
      ) THEN
        ALTER TABLE ${credentialsSql} ADD COLUMN resource TEXT NOT NULL DEFAULT '';
      END IF;
    END $$;
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credentialsResourceIndex)}
    ON ${credentialsSql} (resource)
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'auth_flows')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'verification')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'auth_accounts')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'auth_sessions')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'auth_users')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'auth_verifications')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'issued_tokens')}
  `))

  await db.execute(sql.raw(`
    DROP TABLE IF EXISTS ${qualifyTable(schemaName, 'revocations')}
  `))
}
