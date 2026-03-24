import { beforeEach, describe, expect, it } from 'vitest'
import { createQueryHelpers } from 'agent.pw/sql'
import { deriveEncryptionKey, encryptCredentials } from '../packages/server/src/lib/credentials-crypto'
import { BISCUIT_PRIVATE_KEY, createTestDb, type TestDb } from './setup'

let db: TestDb
const queries = createQueryHelpers()

async function secret(token: string) {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  return encryptCredentials(encryptionKey, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  })
}

beforeEach(async () => {
  db = await createTestDb()
})

describe('query edge cases', () => {
  it('normalizes stored resource patterns on write', async () => {
    await queries.upsertCredProfile(db, '/docs', {
      resourcePatterns: [' https://docs.example.com/* '],
      auth: {
        kind: 'headers',
        fields: [{ name: 'Authorization', label: 'Token', prefix: 'Bearer ' }],
      },
    })

    expect(await queries.getCredProfile(db, '/docs')).toEqual(expect.objectContaining({
      resourcePatterns: ['https://docs.example.com/*'],
    }))
    expect((await queries.listCredProfiles(db)).map(profile => profile.path)).toEqual(['/docs'])
    expect(await queries.deleteCredProfile(db, '/docs')).toBe(true)
    expect(await queries.deleteCredProfile(db, '/docs')).toBe(false)
  })

  it('rejects invalid list paths and still returns direct children for root lists', async () => {
    await queries.upsertCredential(db, {
      path: '/acme/github',
      resource: 'https://api.github.com',
      auth: { kind: 'headers' },
      secret: await secret('gh'),
    })
    await queries.upsertCredential(db, {
      path: '/acme/team/docs',
      resource: 'https://docs.example.com/mcp',
      auth: { kind: 'oauth' },
      secret: await secret('docs'),
    })
    await queries.upsertCredential(db, {
      path: '/top',
      resource: 'https://top.example.com',
      auth: { kind: 'headers' },
      secret: await secret('top'),
    })

    await expect(queries.listCredProfiles(db, { path: '/../bad' })).rejects.toThrow("Invalid path '/../bad'")
    await expect(queries.listCredentials(db, { path: '/../bad' })).rejects.toThrow("Invalid path '/../bad'")

    expect((await queries.listCredentials(db)).map(row => row.path)).toEqual(['/top'])
  })
})
