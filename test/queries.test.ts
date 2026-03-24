import { beforeEach, describe, expect, it } from 'vitest'
import { createQueryHelpers } from 'agent.pw/sql'
import { deriveEncryptionKey, encryptCredentials } from '../packages/server/src/lib/credentials-crypto'
import { BISCUIT_PRIVATE_KEY, createTestDb, type TestDb } from './setup'

let db: TestDb
const queries = createQueryHelpers()

async function encryptedHeaders(token: string) {
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

describe('query layer', () => {
  it('resolves matching profiles by path depth and resource pattern', async () => {
    await queries.upsertCredProfile(db, '/github', {
      resourcePatterns: ['https://api.github.com/*'],
      auth: {
        kind: 'oauth',
        clientId: 'global-client',
        authorizationUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
      },
      displayName: 'GitHub',
    })
    await queries.upsertCredProfile(db, '/acme/github', {
      resourcePatterns: ['https://api.github.com/*'],
      auth: {
        kind: 'headers',
        fields: [{ name: 'Authorization', label: 'Token', prefix: 'Bearer ' }],
      },
      displayName: 'Acme GitHub',
    })
    await queries.upsertCredProfile(db, '/acme/team/github', {
      resourcePatterns: ['https://api.github.com/repos/*'],
      auth: {
        kind: 'headers',
        fields: [{ name: 'Authorization', label: 'Team token', prefix: 'Bearer ' }],
      },
      displayName: 'Team GitHub',
    })

    expect(await queries.getCredProfile(db, '/github')).toEqual(expect.objectContaining({
      path: '/github',
      resourcePatterns: ['https://api.github.com/*'],
    }))

    expect(
      (await queries.getMatchingCredProfiles(db, '/acme/team/connections/docs', 'https://api.github.com/repos/acme/app'))
        .map(profile => profile.path),
    ).toEqual([
      '/acme/team/github',
      '/acme/github',
      '/github',
    ])

    expect(
      (await queries.getMatchingCredProfiles(db, '/beta/docs', 'https://api.github.com/repos/acme/app'))
        .map(profile => profile.path),
    ).toEqual(['/github'])

    expect(await queries.getMatchingCredProfiles(db, '/beta/docs', 'https://gitlab.com/api/v4')).toEqual([])
    expect((await queries.listCredProfiles(db, { path: '/acme' })).map(profile => profile.path)).toEqual([
      '/acme/github',
      '/acme/team/github',
    ])
  })

  it('stores credentials by exact path and lists direct children only', async () => {
    await queries.upsertCredential(db, {
      path: '/acme/connections/github',
      auth: { kind: 'headers', label: 'GitHub', resource: 'https://api.github.com' },
      secret: await encryptedHeaders('github-token'),
    })
    await queries.upsertCredential(db, {
      path: '/acme/connections/team/docs',
      auth: { kind: 'oauth', label: 'Docs', resource: 'https://docs.example.com/mcp' },
      secret: await encryptedHeaders('docs-token'),
    })
    await queries.upsertCredential(db, {
      path: '/acme/elsewhere/notion',
      auth: { kind: 'headers', label: 'Notion', resource: 'https://api.notion.com' },
      secret: await encryptedHeaders('notion-token'),
    })

    expect(await queries.getCredential(db, '/acme/connections/github')).toEqual(expect.objectContaining({
      path: '/acme/connections/github',
      auth: expect.objectContaining({
        resource: 'https://api.github.com/',
      }),
    }))

    expect((await queries.listCredentials(db, { path: '/acme/connections' })).map(row => row.path)).toEqual([
      '/acme/connections/github',
    ])
    expect((await queries.listCredentials(db, { path: '/acme/connections/team' })).map(row => row.path)).toEqual([
      '/acme/connections/team/docs',
    ])
    expect(await queries.listCredentials(db)).toEqual([])

    expect(await queries.moveCredential(db, '/acme/connections/github', '/acme/connections/github_primary')).toBe(true)
    expect(await queries.moveCredential(db, '/acme/connections/github', '/acme/connections/github_secondary')).toBe(false)
    expect(await queries.deleteCredential(db, '/acme/connections/github_primary')).toBe(true)
    expect(await queries.deleteCredential(db, '/acme/connections/github_primary')).toBe(false)
  })
})
