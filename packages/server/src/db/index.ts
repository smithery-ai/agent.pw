import { drizzle as drizzlePg } from 'drizzle-orm/postgres-js'
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite'
import { readFile } from 'node:fs/promises'
import postgres from 'postgres'
import * as schema from './schema/index.js'

type PostgresDatabase = ReturnType<typeof drizzlePg<typeof schema>>
type PgliteDatabase = ReturnType<typeof drizzlePglite<typeof schema>>

/** Database type that works with both postgres-js and PGlite drivers. */
export type Database = PostgresDatabase | PgliteDatabase

/** Create a database connection using postgres-js (for deployed/Smithery mode). */
export function createDb(connectionString: string): Database {
  const client = postgres(connectionString)
  return drizzlePg(client, { schema })
}

let bundledPGliteAssetsPromise: Promise<{
  fsBundle: Blob
  wasmModule: WebAssembly.Module
} | null> | null = null
type WasmByteSource = ArrayBuffer | Uint8Array

async function compileWasmModule(bytes: WasmByteSource): Promise<WebAssembly.Module> {
  const compileFn = Reflect.get(WebAssembly, 'compile')
  if (typeof compileFn === 'function') {
    const module = await compileFn.call(WebAssembly, bytes)
    if (module instanceof WebAssembly.Module) {
      return module
    }
  }

  /* v8 ignore next -- retained only for runtimes without WebAssembly.compile */
  const moduleCtor = Reflect.get(WebAssembly, 'Module')
  if (typeof moduleCtor === 'function') {
    const module = Reflect.construct(moduleCtor, [bytes])
    if (module instanceof WebAssembly.Module) {
      return module
    }
  }

  throw new TypeError('WebAssembly.Module is unavailable in this runtime')
}

async function loadBundledPGliteAssets() {
  const wasmPath = process.env.AGENTPW_PGLITE_WASM_PATH?.trim()
  const dataPath = process.env.AGENTPW_PGLITE_DATA_PATH?.trim()

  if (!(wasmPath && dataPath)) {
    return null
  }

  if (!bundledPGliteAssetsPromise) {
    bundledPGliteAssetsPromise = (async () => {
      const [wasmBytes, dataBytes] = await Promise.all([
        readFile(wasmPath),
        readFile(dataPath),
      ])

      return {
        fsBundle: new Blob([dataBytes], { type: 'application/octet-stream' }),
        wasmModule: await compileWasmModule(wasmBytes),
      }
    })()
  }

  return bundledPGliteAssetsPromise
}

/** Create a local database using PGlite (for CLI/local mode). */
export async function createLocalDb(dataDir: string): Promise<Database> {
  const { PGlite } = await import('@electric-sql/pglite')
  const bundledAssets = await loadBundledPGliteAssets()
  const client = bundledAssets
    ? new PGlite({ dataDir, ...bundledAssets })
    : new PGlite(dataDir)
  return drizzlePglite(client, { schema })
}
