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
  const credProfilesHostIndex = `${credProfilesTable}_host_idx`
  const credentialsHostIndex = `${credentialsTable}_host_idx`
  const credentialsProfilePathIndex = `${credentialsTable}_profile_path_idx`
  const credentialsProfilePathPathIndex = `${credentialsTable}_profile_path_path_idx`
  const credentialsPathPrimaryKey = `${credentialsTable}_path_pk`
  const schemaSql = quoteIdentifier(schemaName)
  const credProfilesSql = qualifyTable(schemaName, credProfilesTable)
  const credentialsSql = qualifyTable(schemaName, credentialsTable)

  await db.execute(sql.raw(`CREATE SCHEMA IF NOT EXISTS ${schemaSql}`))

  await db.execute(sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credProfilesSql} (
      path TEXT PRIMARY KEY,
      host JSONB NOT NULL,
      auth JSONB,
      oauth_config JSONB,
      display_name TEXT,
      description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT now(),
      updated_at TIMESTAMP NOT NULL DEFAULT now()
    )
  `))

  await db.execute(sql.raw(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = '${schemaName}'
          AND table_name = '${credProfilesTable}'
          AND column_name = 'managed_oauth'
      ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = '${schemaName}'
          AND table_name = '${credProfilesTable}'
          AND column_name = 'oauth_config'
      ) THEN
        ALTER TABLE ${credProfilesSql} RENAME COLUMN managed_oauth TO oauth_config;
      END IF;
    END $$;
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesPathIndex)}
    ON ${credProfilesSql} (path)
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credProfilesHostIndex)}
    ON ${credProfilesSql} USING gin (host)
  `))

  await db.execute(sql.raw(`
    CREATE TABLE IF NOT EXISTS ${credentialsSql} (
      path TEXT NOT NULL,
      profile_path TEXT,
      host TEXT,
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
          AND column_name = 'profile_path'
      ) THEN
        ALTER TABLE ${credentialsSql} ADD COLUMN profile_path TEXT;
      END IF;
    END $$;
  `))

  await db.execute(sql.raw(`
    UPDATE ${credentialsSql}
    SET profile_path = path
    WHERE profile_path IS NULL
  `))

  await db.execute(sql.raw(`
    ALTER TABLE ${credentialsSql}
    ALTER COLUMN profile_path SET NOT NULL
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credentialsHostIndex)}
    ON ${credentialsSql} (host)
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credentialsProfilePathIndex)}
    ON ${credentialsSql} (profile_path)
  `))

  await db.execute(sql.raw(`
    CREATE INDEX IF NOT EXISTS ${quoteIdentifier(credentialsProfilePathPathIndex)}
    ON ${credentialsSql} (profile_path, path)
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
