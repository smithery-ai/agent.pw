import { mkdtemp, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { sql } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { errorOfAsync, mustAsync } from "./support/results";

const require = createRequire(import.meta.url);
const pgliteDistDir = dirname(require.resolve("@electric-sql/pglite"));
const bundledWasmPath = join(pgliteDistDir, "postgres.wasm");
const bundledDataPath = join(pgliteDistDir, "postgres.data");

function stubBundledAssetEnv() {
  vi.stubEnv("AGENTPW_PGLITE_WASM_PATH", bundledWasmPath);
  vi.stubEnv("AGENTPW_PGLITE_DATA_PATH", bundledDataPath);
}

function stubWebAssembly(overrides: { compile?: unknown; Module?: unknown }) {
  vi.stubGlobal(
    "WebAssembly",
    Object.assign(Object.create(WebAssembly), {
      compile: WebAssembly.compile,
      Module: WebAssembly.Module,
      ...overrides,
    }),
  );
}

async function withLocalDb(run: (db: Awaited<ReturnType<typeof mustAsync>>) => Promise<void>) {
  const dataDir = await mkdtemp(join(tmpdir(), "agentpw-pglite-assets-"));
  let db: {
    execute: typeof run extends (db: infer T) => Promise<void> ? T["execute"] : never;
    $client?: { close?: () => Promise<void> };
  } | null = null;

  try {
    const { createLocalDb } = await import("../packages/server/src/db/index");
    db = await mustAsync(createLocalDb(dataDir));
    await run(db);
  } finally {
    await db?.$client?.close?.();
    await rm(dataDir, { recursive: true, force: true });
  }
}

describe("bundled PGlite assets", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("uses bundled assets when env paths are configured", async () => {
    stubBundledAssetEnv();

    await withLocalDb(async (db) => {
      const result = await db.execute(sql`select 1 as value`);
      expect(result.rows).toEqual([{ value: 1 }]);
    });
  }, 15_000);

  it("accepts bundled wasm assets returned as ArrayBuffer", async () => {
    stubBundledAssetEnv();
    vi.doMock("node:fs/promises", async () => {
      const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
      return {
        ...actual,
        readFile: vi.fn(async (path, options) => {
          const bytes = await actual.readFile(path, options);
          if (
            (String(path) !== bundledWasmPath && String(path) !== bundledDataPath) ||
            !(bytes instanceof Uint8Array)
          ) {
            return bytes;
          }
          return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        }),
      };
    });

    await withLocalDb(async (db) => {
      const result = await db.execute(sql`select 1 as value`);
      expect(result.rows).toEqual([{ value: 1 }]);
    });
  });

  it("falls back to the WebAssembly.Module constructor when compile is unavailable", async () => {
    stubBundledAssetEnv();
    stubWebAssembly({ compile: undefined });

    await withLocalDb(async (db) => {
      const result = await db.execute(sql`select 1 as value`);
      expect(result.rows).toEqual([{ value: 1 }]);
    });
  });

  it("returns an internal error when no WebAssembly module compiler is available", async () => {
    stubBundledAssetEnv();
    stubWebAssembly({ compile: undefined, Module: undefined });

    const { createLocalDb } = await import("../packages/server/src/db/index");

    expect((await errorOfAsync(createLocalDb("/tmp/agentpw-data"))).message).toBe(
      "WebAssembly.Module is unavailable in this runtime",
    );
  });

  it("falls back to the plain PGlite constructor when no asset env vars are set", async () => {
    await withLocalDb(async (db) => {
      const result = await db.execute(sql`select 1 as value`);
      expect(result.rows).toEqual([{ value: 1 }]);
    });
  });
});
