import { describe, expect, it } from 'vitest'
import { sql } from 'drizzle-orm'
import {
  createIssuedToken,
  getCredProfile,
  getIssuedTokenByHash,
  getIssuedTokenById,
  getIssuedTokenByIdUnscoped,
  isMissingIssuedTokensTableError,
  listCredentials,
  listCredentialsAccessiblePage,
  listCredProfiles,
  listIssuedTokensByOwner,
  markIssuedTokenUsedBestEffort,
  moveCredential,
  revokeIssuedTokenById,
  revokeIssuedTokenByIdUnscoped,
  upsertCredential,
} from 'agent.pw/sql'
import { hashToken, mintToken } from 'agent.pw/access'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

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
      host: 'api.linear.app',
      path: '/org_alpha/a',
      auth: { kind: 'headers' },
      secret: Buffer.from('a'),
    })
    await upsertCredential(db, {
      host: 'api.linear.app',
      path: '/org_alpha/b',
      auth: { kind: 'headers' },
      secret: Buffer.from('b'),
    })
    await upsertCredential(db, {
      host: 'api.linear.app',
      path: '/org_beta/c',
      auth: { kind: 'headers' },
      secret: Buffer.from('c'),
    })
    await upsertCredential(db, {
      host: 'api.secondary.app',
      path: '/org_alpha/shared',
      auth: { kind: 'headers' },
      secret: Buffer.from('d'),
    })
    await upsertCredential(db, {
      host: 'api.tertiary.app',
      path: '/org_alpha/shared',
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
      '/org_alpha/shared',
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
      limit: 5,
      roots: ['/'],
    })).toEqual(expect.objectContaining({
      hasMore: false,
      items: expect.arrayContaining([
        expect.objectContaining({ path: '/org_alpha/a' }),
        expect.objectContaining({ path: '/org_alpha/b' }),
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
      '/org_alpha/shared',
    ])
    expect(secondPage.hasMore).toBe(false)
  })

  it('handles token ledger misses, missing tables, and revocation edge cases', async () => {
    const db = await createTestDb()
    const token = mintToken(BISCUIT_PRIVATE_KEY, 'user_alpha', [
      { action: 'credential.use', root: '/org_alpha' },
    ])
    const tokenHash = await hashToken(token)

    expect(await getIssuedTokenById(db, 'missing', {
      ownerUserId: 'user_alpha',
      orgId: 'org_alpha',
    })).toBeNull()
    expect(await getIssuedTokenByIdUnscoped(db, 'missing')).toBeNull()
    expect(await getIssuedTokenByHash(db, 'missing')).toBeNull()
    expect(await listIssuedTokensByOwner(db, {})).toEqual([])

    await createIssuedToken(db, {
      id: 'tok_empty',
      ownerUserId: 'user_alpha',
      orgId: null,
      tokenHash,
      revocationIds: [],
      rights: [{ action: 'credential.use', root: '/org_alpha' }],
      constraints: [],
    })

    expect(await revokeIssuedTokenById(db, 'tok_empty', {
      ownerUserId: 'other_user',
    }, 'manual')).toBeNull()

    const revoked = await revokeIssuedTokenByIdUnscoped(db, 'tok_empty', 'manual')
    expect(revoked).toEqual(expect.objectContaining({
      id: 'tok_empty',
      revokeReason: 'manual',
    }))

    const revokedAgain = await revokeIssuedTokenByIdUnscoped(db, 'tok_empty', 'ignored')
    expect(revokedAgain).toEqual(expect.objectContaining({
      id: 'tok_empty',
      revokeReason: 'manual',
      revokedAt: revoked?.revokedAt,
    }))

    expect(await moveCredential(db, 'missing.host', '/missing', '/next')).toBe(false)

    await createIssuedToken(db, {
      id: 'tok_null_reason',
      ownerUserId: 'user_alpha',
      orgId: null,
      tokenHash: `${tokenHash}-2`,
      revocationIds: [],
      rights: [{ action: 'credential.use', root: '/org_alpha' }],
      constraints: [],
    })
    expect(await revokeIssuedTokenByIdUnscoped(db, 'tok_null_reason')).toEqual(expect.objectContaining({
      id: 'tok_null_reason',
      revokeReason: null,
    }))

    expect(isMissingIssuedTokensTableError({
      cause: new Error('relation "agentpw.issued_tokens" does not exist'),
    })).toBe(true)
    expect(isMissingIssuedTokensTableError({ code: '42P01' })).toBe(true)
    expect(isMissingIssuedTokensTableError('no such table: issued_tokens')).toBe(true)
    expect(isMissingIssuedTokensTableError({ code: 'XX000' })).toBe(false)

    const missingTableDb = {
      update() {
        throw { code: '42P01' }
      },
    }
    await expect(markIssuedTokenUsedBestEffort(missingTableDb as never, 'hash')).resolves.toBeNull()

    const brokenDb = {
      update() {
        throw new Error('boom')
      },
    }
    await expect(markIssuedTokenUsedBestEffort(brokenDb as never, 'hash')).rejects.toThrow('boom')
  })
})
