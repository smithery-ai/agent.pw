import { migrate } from 'drizzle-orm/pglite/migrator'
import { join } from 'node:path'
import type { Database } from './index'

/** Run all drizzle migrations on a local PGlite database. */
export async function migrateLocal(db: Database) {
  const migrationsFolder = join(import.meta.dirname, '../../drizzle')
  await migrate(db as any, { migrationsFolder })
}
