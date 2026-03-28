import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { errorOfAsync, mustAsync } from "./support/results";

const { FakePGlite, drizzlePglite, pgliteCtor, readFile } = vi.hoisted(() => {
  const pgliteCtor = vi.fn();

  class FakePGlite {
    constructor(arg: unknown) {
      pgliteCtor(arg);
    }
  }

  return {
    FakePGlite,
    drizzlePglite: vi.fn((client: unknown) => ({ $client: client })),
    pgliteCtor,
    readFile: vi.fn(),
  };
});

vi.mock("node:fs/promises", () => ({
  readFile,
}));

vi.mock("@electric-sql/pglite", () => ({
  PGlite: FakePGlite,
}));

vi.mock("@electric-sql/pglite/contrib/ltree", () => ({
  ltree: { name: "ltree-extension" },
}));

vi.mock("drizzle-orm/pglite", () => ({
  drizzle: drizzlePglite,
}));

const wasmBytes = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
const dataBytes = Buffer.from("pglite-data");

function stubBundledAssetReads() {
  vi.stubEnv("AGENTPW_PGLITE_WASM_PATH", "/tmp/postgres.wasm");
  vi.stubEnv("AGENTPW_PGLITE_DATA_PATH", "/tmp/postgres.data");

  readFile.mockImplementation(async (filePath: string) =>
    filePath.endsWith(".wasm") ? wasmBytes : dataBytes,
  );
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

describe("bundled PGlite assets", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("uses bundled assets when env paths are configured", async () => {
    stubBundledAssetReads();

    const { createLocalDb } = await import("../packages/server/src/db/index");
    const db = await mustAsync(createLocalDb("/tmp/agentpw-data"));

    expect(readFile).toHaveBeenCalledTimes(2);
    expect(pgliteCtor).toHaveBeenCalledTimes(1);

    const args = pgliteCtor.mock.calls[0][0] as {
      dataDir: string;
      extensions: Record<string, unknown>;
      fsBundle: Blob;
      wasmModule: WebAssembly.Module;
    };

    expect(args.dataDir).toBe("/tmp/agentpw-data");
    expect(args.extensions).toEqual({ ltree: { name: "ltree-extension" } });
    expect(args.fsBundle).toBeInstanceOf(Blob);
    expect(args.wasmModule).toBeInstanceOf(WebAssembly.Module);
    expect(drizzlePglite).toHaveBeenCalledWith(expect.any(FakePGlite), expect.any(Object));
    expect(db).toEqual({ $client: expect.any(FakePGlite) });
  });

  it("falls back to the WebAssembly.Module constructor when compile is unavailable", async () => {
    stubBundledAssetReads();
    stubWebAssembly({ compile: undefined });

    const { createLocalDb } = await import("../packages/server/src/db/index");
    const db = await mustAsync(createLocalDb("/tmp/agentpw-data"));

    expect(pgliteCtor).toHaveBeenCalledTimes(1);

    const args = pgliteCtor.mock.calls[0][0] as {
      dataDir: string;
      extensions: Record<string, unknown>;
      fsBundle: Blob;
      wasmModule: WebAssembly.Module;
    };

    expect(args.dataDir).toBe("/tmp/agentpw-data");
    expect(args.extensions).toEqual({ ltree: { name: "ltree-extension" } });
    expect(args.fsBundle).toBeInstanceOf(Blob);
    expect(args.wasmModule).toBeInstanceOf(WebAssembly.Module);
    expect(drizzlePglite).toHaveBeenCalledWith(expect.any(FakePGlite), expect.any(Object));
    expect(db).toEqual({ $client: expect.any(FakePGlite) });
  });

  it("returns an internal error when no WebAssembly module compiler is available", async () => {
    stubBundledAssetReads();
    stubWebAssembly({ compile: undefined, Module: undefined });

    const { createLocalDb } = await import("../packages/server/src/db/index");

    expect((await errorOfAsync(createLocalDb("/tmp/agentpw-data"))).message).toBe(
      "WebAssembly.Module is unavailable in this runtime",
    );
    expect(pgliteCtor).not.toHaveBeenCalled();
  });

  it("falls back to the plain PGlite constructor when no asset env vars are set", async () => {
    const { createLocalDb } = await import("../packages/server/src/db/index");
    const db = await mustAsync(createLocalDb("/tmp/plain-data"));

    expect(readFile).not.toHaveBeenCalled();
    expect(pgliteCtor).toHaveBeenCalledWith({
      dataDir: "/tmp/plain-data",
      extensions: { ltree: { name: "ltree-extension" } },
    });
    expect(drizzlePglite).toHaveBeenCalledWith(expect.any(FakePGlite), expect.any(Object));
    expect(db).toEqual({ $client: expect.any(FakePGlite) });
  });
});
