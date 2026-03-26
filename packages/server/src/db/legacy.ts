import { sql } from 'drizzle-orm'
import type { SqlNamespaceOptions } from '../types.js'
import { coerceSqlNamespace, type AgentPwSqlNamespace } from './schema/index.js'
import type { Database } from './index.js'

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace

function quoteIdentifier(identifier: string) {
  return `"${identifier.replaceAll('"', '""')}"`
}

function quoteLiteral(identifier: string) {
  return `'${identifier.replaceAll("'", "''")}'`
}

function qualifyTable(schema: string, tableName: string) {
  return `${quoteIdentifier(schema)}.${quoteIdentifier(tableName)}`
}

export async function backfillCredentialResourcesToAuth(
  db: Database,
  options: {
    sql?: SqlNamespaceInput
  } = {},
) {
  const sqlNamespace = coerceSqlNamespace(options.sql)
  const schemaName = sqlNamespace.schema
  const credentialsTable = sqlNamespace.tableName('credentials')
  const credentialsSql = qualifyTable(schemaName, credentialsTable)

  await db.execute(sql.raw(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = ${quoteLiteral(schemaName)}
          AND table_name = ${quoteLiteral(credentialsTable)}
          AND column_name = 'resource'
      ) THEN
        EXECUTE ${quoteLiteral(`
          UPDATE ${credentialsSql}
          SET auth = jsonb_set(auth, '{resource}', to_jsonb(resource), true)
          WHERE coalesce(resource, '') <> ''
            AND coalesce(auth->>'resource', '') = ''
            AND coalesce(auth->>'kind', '') IN ('oauth', 'headers')
        `)};
      END IF;
    END $$;
  `))
}
