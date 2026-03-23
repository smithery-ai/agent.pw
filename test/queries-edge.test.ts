import { describe, expect, it } from 'vitest'
import { sql } from 'drizzle-orm'
import {
  getCredProfile,
  listCredentials,
  listCredentialsAccessiblePage,
  listCredProfiles,
  moveCredential,
  upsertCredential,
} from 'agent.pw/sql'
import { createTestDb } from './setup'

describe('query edge cases', () => {
  it('normalizes odd profile host shapes and paginates accessible credentials', async () => {
    const db = await createTestDb()

    await db.execute(sql`
      insert into agentpw.cred_profiles (path, host)
      values ('/github', '"api.github.com"'::jsonb), ('/gitlab', '[""]'::jsonb), ('/slack', '{}'::jsonb)
    `)

    expect(await getCredProfile(db, '/github')).toEqual(expect.objectContaining({
      host: ['api.github.com'],
    }))
    expect(await getCredProfile(db, '/gitlab')).toEqual(expect.objectContaining({
      host: [],
    }))
    expect(await getCredProfile(db, '/slack')).toEqual(expect.objectContaining({
      host: [],
    }))
    expect(await getCredProfile(db, '/missing')).toBeNull()
    expect((await listCredProfiles(db)).map(profile => profile.path)).toEqual(['/github', '/gitlab', '/slack'])

    await upsertCredential(db, {
      profilePath: '/linear',
      host: 'api.linear.app',
      path: '/org_alpha/a',
      auth: { kind: 'headers' },
      secret: Buffer.from('a'),
    })
    await upsertCredential(db, {
      profilePath: '/linear',
      host: 'api.linear.app',
      path: '/org_alpha/b',
      auth: { kind: 'headers' },
      secret: Buffer.from('b'),
    })
    await upsertCredential(db, {
      profilePath: '/linear',
      host: 'api.linear.app',
      path: '/org_beta/c',
      auth: { kind: 'headers' },
      secret: Buffer.from('c'),
    })
    await upsertCredential(db, {
      profilePath: '/secondary',
      host: 'api.secondary.app',
      path: '/org_alpha/shared',
      auth: { kind: 'headers' },
      secret: Buffer.from('d'),
    })
    await upsertCredential(db, {
      profilePath: '/tertiary',
      host: null,
      path: '/org_alpha/shared-secondary',
      auth: { kind: 'headers' },
      secret: Buffer.from('e'),
    })
    await db.execute(sql`
      update agentpw.credentials
      set created_at = case path
        when '/org_alpha/a' then '2026-01-03T00:00:00.000Z'::timestamp
        when '/org_alpha/b' then '2026-01-02T00:00:00.000Z'::timestamp
        else '2026-01-01T00:00:00.000Z'::timestamp
      end
    `)

    expect((await listCredentials(db)).map(row => row.path)).toEqual([
      '/org_alpha/a',
      '/org_alpha/b',
      '/org_alpha/shared',
      '/org_alpha/shared-secondary',
      '/org_beta/c',
    ])

    expect(await listCredentialsAccessiblePage(db, {
      limit: 5,
      roots: [],
    })).toEqual({
      items: [],
      hasMore: false,
    })

    expect(await listCredentialsAccessiblePage(db, {
      limit: 10,
      roots: ['/'],
    })).toEqual(expect.objectContaining({
      hasMore: false,
      items: expect.arrayContaining([
        expect.objectContaining({ path: '/org_alpha/a' }),
        expect.objectContaining({ path: '/org_beta/c' }),
      ]),
    }))

    const firstPage = await listCredentialsAccessiblePage(db, {
      limit: 1,
      roots: ['/org_alpha', '/org_beta'],
      pathPrefix: '/org_alpha',
    })
    expect(firstPage.items).toHaveLength(1)
    expect(firstPage.hasMore).toBe(true)

    const cursor = firstPage.items[0]
    const secondPage = await listCredentialsAccessiblePage(db, {
      limit: 5,
      roots: ['/org_alpha', '/org_beta'],
      pathPrefix: '/org_alpha',
      after: {
        createdAt: cursor.createdAt,
        path: cursor.path,
        host: cursor.host,
      },
    })
    expect(secondPage.items.map(item => item.path)).toEqual([
      '/org_alpha/b',
      '/org_alpha/shared',
      '/org_alpha/shared-secondary',
    ])
    expect(secondPage.hasMore).toBe(false)

    const nullHostCursorPage = await listCredentialsAccessiblePage(db, {
      limit: 5,
      roots: ['/org_alpha', '/org_beta'],
      after: {
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        path: '/org_alpha/shared',
        host: null,
      },
    })
    expect(nullHostCursorPage.items.map(item => item.path)).toContain('/org_alpha/shared-secondary')

    expect(await moveCredential(db, '/missing', '/next')).toBe(false)
  })
})
