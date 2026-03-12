import type { Database } from './index'
import { bootstrapLocalSchema } from './bootstrap-local'

/** Bootstrap the local PGlite schema for OSS without checked-in Drizzle migrations. */
export async function migrateLocal(db: Database) {
  await bootstrapLocalSchema(db)
}
