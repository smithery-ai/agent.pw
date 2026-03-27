import { err, ok, result, type Result } from "okay-error";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { drizzle as drizzlePg } from "drizzle-orm/postgres-js";
import { readFile } from "node:fs/promises";
import postgres from "postgres";
import { internalError } from "../errors.js";
import type { SqlNamespaceOptions } from "../types.js";
import { coerceSqlNamespace, type AgentPwSqlNamespace, type schemaTables } from "./schema/index.js";

type PostgresDatabase = ReturnType<typeof drizzlePg<typeof schemaTables>>;
type PgliteDatabase = ReturnType<typeof drizzlePglite<typeof schemaTables>>;

export type Database = PostgresDatabase | PgliteDatabase;

type SqlNamespaceInput = SqlNamespaceOptions | AgentPwSqlNamespace;

export function createDb(
  connectionString: string,
  options: {
    sql?: SqlNamespaceInput;
  } = {},
) {
  const sqlNamespace = coerceSqlNamespace(options.sql);
  if (!sqlNamespace.ok) {
    return sqlNamespace;
  }

  return ok(drizzlePg(postgres(connectionString), { schema: sqlNamespace.value.tables }));
}

let bundledPGliteAssetsPromise: Promise<
  Result<{
    fsBundle: Blob;
    wasmModule: WebAssembly.Module;
  } | null>
> | null = null;
type WasmByteSource = ArrayBuffer | Uint8Array;

async function compileWasmModule(bytes: WasmByteSource) {
  const compileFn = Reflect.get(WebAssembly, "compile");
  if (typeof compileFn === "function") {
    const module = await compileFn.call(WebAssembly, bytes);
    if (module instanceof WebAssembly.Module) {
      return ok(module);
    }
  }

  const moduleCtor = Reflect.get(WebAssembly, "Module");
  if (typeof moduleCtor === "function") {
    const module = Reflect.construct(moduleCtor, [bytes]);
    if (module instanceof WebAssembly.Module) {
      return ok(module);
    }
  }

  return err(
    internalError("WebAssembly.Module is unavailable in this runtime", {
      source: "db.compileWasmModule",
    }),
  );
}

async function loadBundledPGliteAssets() {
  const wasmPath = process.env.AGENTPW_PGLITE_WASM_PATH?.trim();
  const dataPath = process.env.AGENTPW_PGLITE_DATA_PATH?.trim();

  if (!(wasmPath && dataPath)) {
    return ok(null);
  }

  if (!bundledPGliteAssetsPromise) {
    bundledPGliteAssetsPromise = (async () => {
      const bytes = await result(Promise.all([readFile(wasmPath), readFile(dataPath)]));
      if (!bytes.ok) {
        return err(
          internalError("Failed to read bundled PGlite assets", {
            cause: bytes.error,
            source: "db.loadBundledPGliteAssets",
          }),
        );
      }

      const wasmModule = await compileWasmModule(bytes.value[0]);
      if (!wasmModule.ok) {
        return wasmModule;
      }

      return ok({
        fsBundle: new Blob([bytes.value[1]], { type: "application/octet-stream" }),
        wasmModule: wasmModule.value,
      });
    })();
  }

  return bundledPGliteAssetsPromise;
}

export async function createLocalDb(
  dataDir: string,
  options: {
    sql?: SqlNamespaceInput;
  } = {},
) {
  const imported = await result(import("@electric-sql/pglite"));
  if (!imported.ok) {
    return err(
      internalError("Failed to load @electric-sql/pglite", {
        cause: imported.error,
        source: "db.createLocalDb.import",
      }),
    );
  }

  const sqlNamespace = coerceSqlNamespace(options.sql);
  if (!sqlNamespace.ok) {
    return sqlNamespace;
  }

  const bundledAssets = await loadBundledPGliteAssets();
  if (!bundledAssets.ok) {
    return bundledAssets;
  }

  const client = bundledAssets.value
    ? new imported.value.PGlite({ dataDir, ...bundledAssets.value })
    : new imported.value.PGlite(dataDir);
  return ok(drizzlePglite(client, { schema: sqlNamespace.value.tables }));
}
