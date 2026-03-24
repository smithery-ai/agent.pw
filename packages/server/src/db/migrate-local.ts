import type { SqlNamespaceOptions } from '../types.js'
import type { Database } from './index'
import { bootstrapLocalSchema } from './bootstrap-local'
import type { AgentPwSqlNamespace } from './schema/index.js'

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace

/** Bootstrap the local PGlite schema for OSS without checked-in Drizzle migrations. */
export async function migrateLocal(
  db: Database,
  options: {
    sql?: SqlNamespaceInput
  } = {},
) {
  await bootstrapLocalSchema(db, options)
}
