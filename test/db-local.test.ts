import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, expect, it, vi } from 'vitest'
import { sql } from 'drizzle-orm'
import { createDb, createLocalDb } from '@agent.pw/server/db'

async function closeLocalDb(db: unknown) {
  await (db as { $client?: { close?: () => Promise<void> } }).$client?.close?.()
}

describe('db entrypoints', () => {
  it('creates postgres-js and local PGlite database handles', async () => {
    const remoteDb = createDb('postgres://user:pass@127.0.0.1:5432/agentpw')
    expect(typeof remoteDb.execute).toBe('function')

    let localDb: Awaited<ReturnType<typeof createLocalDb>> | undefined
    const dataDir = await mkdtemp(join(tmpdir(), 'agentpw-pglite-'))
    try {
      localDb = await createLocalDb(dataDir)
      const result = await localDb.execute(sql`select 1 as value`)
      expect(result.rows).toEqual([{ value: 1 }])
    } finally {
      await closeLocalDb(localDb)
      await rm(dataDir, { recursive: true, force: true })
    }
  })

  it('runs local drizzle migrations from the repo root', async () => {
    let db: Awaited<ReturnType<typeof createLocalDb>> | undefined
    const dataDir = await mkdtemp(join(tmpdir(), 'agentpw-migrate-'))
    try {
      vi.resetModules()
      vi.doMock('drizzle-orm/pglite/migrator', () => ({
        migrate: vi.fn().mockResolvedValue(undefined),
      }))

      const { migrateLocal } = await import('@agent.pw/server/db/migrate-local')
      const { migrate } = await import('drizzle-orm/pglite/migrator')
      db = await createLocalDb(dataDir)
      await migrateLocal(db)
      expect(migrate).toHaveBeenCalledWith(expect.anything(), {
        migrationsFolder: expect.stringMatching(/[\\/]drizzle$/),
      })
    } finally {
      await closeLocalDb(db)
      await rm(dataDir, { recursive: true, force: true })
    }
  })
})
