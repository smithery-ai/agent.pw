import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  FakePGlite,
  drizzlePglite,
  pgliteCtor,
  readFile,
} = vi.hoisted(() => {
  const pgliteCtor = vi.fn()

  class FakePGlite {
    constructor(arg: unknown) {
      pgliteCtor(arg)
    }
  }

  return {
    FakePGlite,
    drizzlePglite: vi.fn((client: unknown) => ({ $client: client })),
    pgliteCtor,
    readFile: vi.fn(),
  }
})

vi.mock('node:fs/promises', () => ({
  readFile,
}))

vi.mock('@electric-sql/pglite', () => ({
  PGlite: FakePGlite,
}))

vi.mock('drizzle-orm/pglite', () => ({
  drizzle: drizzlePglite,
}))

describe('bundled PGlite assets', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    vi.unstubAllEnvs()
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('uses bundled assets when env paths are configured', async () => {
    const wasmBytes = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
    const dataBytes = Buffer.from('pglite-data')

    vi.stubEnv('AGENTPW_PGLITE_WASM_PATH', '/tmp/postgres.wasm')
    vi.stubEnv('AGENTPW_PGLITE_DATA_PATH', '/tmp/postgres.data')

    readFile.mockImplementation(async (filePath: string) => (
      filePath.endsWith('.wasm') ? wasmBytes : dataBytes
    ))

    const { createLocalDb } = await import('../packages/server/src/db/index')
    const db = await createLocalDb('/tmp/agentpw-data')

    expect(readFile).toHaveBeenCalledTimes(2)
    expect(pgliteCtor).toHaveBeenCalledTimes(1)

    const args = pgliteCtor.mock.calls[0][0] as {
      dataDir: string
      fsBundle: Blob
      wasmModule: WebAssembly.Module
    }

    expect(args.dataDir).toBe('/tmp/agentpw-data')
    expect(args.fsBundle).toBeInstanceOf(Blob)
    expect(args.wasmModule).toBeInstanceOf(WebAssembly.Module)
    expect(drizzlePglite).toHaveBeenCalledWith(expect.any(FakePGlite), expect.any(Object))
    expect(db).toEqual({ $client: expect.any(FakePGlite) })
  })

  it('falls back to the plain PGlite constructor when no asset env vars are set', async () => {
    const { createLocalDb } = await import('../packages/server/src/db/index')
    const db = await createLocalDb('/tmp/plain-data')

    expect(readFile).not.toHaveBeenCalled()
    expect(pgliteCtor).toHaveBeenCalledWith('/tmp/plain-data')
    expect(drizzlePglite).toHaveBeenCalledWith(expect.any(FakePGlite), expect.any(Object))
    expect(db).toEqual({ $client: expect.any(FakePGlite) })
  })
})
