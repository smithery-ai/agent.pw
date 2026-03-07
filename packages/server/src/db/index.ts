import { drizzle as drizzlePg } from 'drizzle-orm/postgres-js'
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite'
import postgres from 'postgres'
import * as schema from './schema'

type PostgresDatabase = ReturnType<typeof drizzlePg<typeof schema>>
type PgliteDatabase = ReturnType<typeof drizzlePglite<typeof schema>>

/** Database type that works with both postgres-js and PGlite drivers. */
export type Database = PostgresDatabase | PgliteDatabase

/** Create a database connection using postgres-js (for deployed/Smithery mode). */
export function createDb(connectionString: string): Database {
  const client = postgres(connectionString)
  return drizzlePg(client, { schema })
}

/** Create a local database using PGlite (for CLI/local mode). */
export async function createLocalDb(dataDir: string): Promise<Database> {
  const { PGlite } = await import('@electric-sql/pglite')
  const client = new PGlite(dataDir)
  return drizzlePglite(client, { schema })
}
