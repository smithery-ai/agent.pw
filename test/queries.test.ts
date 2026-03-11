import { beforeEach, describe, expect, it } from 'vitest'
import { sql } from 'drizzle-orm'
import {
  completeAuthFlow,
  createAuthFlow,
  deleteCredential,
  getAuthFlow,
  getCredProfile,
  getCredProfileByHost,
  getCredProfilesByHostWithinRoot,
  getCredProfilesBySlugWithPublicFallback,
  getCredential,
  getCredentialsByHost,
  getCredentialsByHostWithinRoot,
  isRevoked,
  listCredProfilesWithCredentialCounts,
  listCredProfilesPage,
  listCredentials,
  listCredentialsAccessible,
  listCredentialsAccessiblePage,
  listCredentialsWithinRoots,
  revokeToken,
  upsertCredProfile,
  upsertCredential,
} from '@agent.pw/server/db/queries'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '@agent.pw/server/crypto'
import { publicProfilePath } from '@agent.pw/server/paths'
import {
  BISCUIT_PRIVATE_KEY,
  createTestDb,
  type TestDb,
} from './setup'

let db: TestDb

async function storeBearerCredential(host: string, path: string, token: string) {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const secret = await encryptCredentials(encryptionKey, {
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, token),
  })

  await upsertCredential(db, {
    host,
    path,
    auth: { kind: 'headers' },
    secret,
  })
}

beforeEach(async () => {
  db = await createTestDb()
})

describe('db queries', () => {
  it('handles profile lookups and visibility', async () => {
    await upsertCredProfile(db, publicProfilePath('global'), {
      host: ['api.global.com', 'api.shared.com'],
      displayName: 'Global',
      description: 'root profile',
    })
    await upsertCredProfile(db, '/org_alpha/team/service', {
      host: ['api.team.com'],
      auth: { authSchemes: [{ type: 'http', scheme: 'bearer' }] },
      displayName: 'Team',
    })

    await storeBearerCredential('api.global.com', '/global-cred', 'global-token')
    await storeBearerCredential('api.shared.com', '/shared-cred', 'shared-token')

    expect(await getCredProfile(db, publicProfilePath('global'))).toEqual(
      expect.objectContaining({ path: publicProfilePath('global') }),
    )
    expect(await getCredProfileByHost(db, 'api.global.com')).toEqual(
      expect.objectContaining({ path: publicProfilePath('global') }),
    )
    expect(await getCredProfileByHost(db, 'missing.example.com')).toBeNull()
    expect((await getCredProfilesByHostWithinRoot(db, 'api.team.com', '/org_alpha/team')).map(profile => profile.path)).toEqual([
      '/org_alpha/team/service',
    ])
    expect(await getCredProfilesByHostWithinRoot(db, 'api.team.com', '/org_beta')).toEqual([])
    expect((await getCredProfilesBySlugWithPublicFallback(db, 'global', '/org_beta')).map(profile => profile.path)).toEqual([
      publicProfilePath('global'),
    ])
    expect((await getCredProfilesBySlugWithPublicFallback(db, 'service', '/org_alpha/team/deeper')).map(profile => profile.path)).toEqual([
      '/org_alpha/team/service',
    ])

    const countedProfiles = await listCredProfilesWithCredentialCounts(db)
    expect(countedProfiles.find(profile => profile.path === publicProfilePath('global'))?.credentialCount).toBe(2)
  })

  it('handles credential queries within explicit descendant roots', async () => {
    await storeBearerCredential('api.example.com', '/root-cred', 'root-token')
    await storeBearerCredential('api.example.com', '/org_alpha/org-cred', 'org-token')
    await storeBearerCredential('api.example.com', '/org_alpha/team/team-cred', 'team-token')
    await storeBearerCredential('api.example.com', '/org_beta/other-cred', 'other-token')

    expect(await getCredential(db, 'api.example.com', '/org_alpha/org-cred')).toEqual(
      expect.objectContaining({ path: '/org_alpha/org-cred' }),
    )
    expect((await getCredentialsByHost(db, 'api.example.com')).length).toBe(4)
    expect((await listCredentials(db)).length).toBe(4)

    const adminAccessible = await listCredentialsWithinRoots(db, ['/org_alpha'])
    expect(adminAccessible.map(credential => credential.path)).toEqual(
      expect.arrayContaining(['/org_alpha/org-cred', '/org_alpha/team/team-cred']),
    )
    expect(adminAccessible.map(credential => credential.path)).not.toContain('/root-cred')

    const accessible = await listCredentialsAccessible(db, ['/org_alpha/team'])
    expect(accessible.map(credential => credential.path)).toEqual(['/org_alpha/team/team-cred'])

    expect((await getCredentialsByHostWithinRoot(db, 'api.example.com', '/org_alpha')).map(credential => credential.path)).toEqual([
      '/org_alpha/team/team-cred',
      '/org_alpha/org-cred',
    ])

    expect(await deleteCredential(db, 'api.example.com', '/org_alpha/org-cred')).toBe(true)
    expect(await deleteCredential(db, 'api.example.com', '/org_alpha/org-cred')).toBe(false)
  })

  it('pages profile and credential listings at the query layer', async () => {
    for (const slug of ['aaa', 'bbb', 'ccc']) {
      await upsertCredProfile(db, `/${slug}`, {
        host: [`api.${slug}.com`],
      })
    }

    const firstProfilePage = await listCredProfilesPage(db, {
      limit: 2,
      visibleRoots: ['/'],
    })
    expect(firstProfilePage.items.map(profile => profile.path)).toEqual(['/aaa', '/bbb'])
    expect(firstProfilePage.hasMore).toBe(true)

    const secondProfilePage = await listCredProfilesPage(db, {
      limit: 2,
      visibleRoots: ['/'],
      afterPath: firstProfilePage.items[firstProfilePage.items.length - 1]!.path,
    })
    expect(secondProfilePage.items.map(profile => profile.path)).toEqual(['/ccc'])
    expect(secondProfilePage.hasMore).toBe(false)

    await storeBearerCredential('api.example.com', '/org_alpha/cred-a', 'token-a')
    await storeBearerCredential('api.example.com', '/org_alpha/cred-b', 'token-b')
    await storeBearerCredential('api.example.com', '/org_alpha/cred-c', 'token-c')

    const firstCredentialPage = await listCredentialsAccessiblePage(db, {
      limit: 2,
      roots: ['/org_alpha'],
    })
    expect(firstCredentialPage.items).toHaveLength(2)
    expect(firstCredentialPage.hasMore).toBe(true)

    const lastCredential = firstCredentialPage.items[firstCredentialPage.items.length - 1]!
    const secondCredentialPage = await listCredentialsAccessiblePage(db, {
      limit: 2,
      roots: ['/org_alpha'],
      after: {
        createdAt: lastCredential.createdAt,
        path: lastCredential.path,
        host: lastCredential.host,
      },
    })
    expect(secondCredentialPage.items).toHaveLength(1)
    expect(secondCredentialPage.hasMore).toBe(false)

    expect([
      ...firstCredentialPage.items.map(credential => credential.path),
      ...secondCredentialPage.items.map(credential => credential.path),
    ]).toEqual(expect.arrayContaining(['/org_alpha/cred-a', '/org_alpha/cred-b', '/org_alpha/cred-c']))
  })

  it('resolves profile applicability from the active root cascade', async () => {
    await upsertCredProfile(db, '/linear', {
      host: ['api.linear.global'],
      displayName: 'Global Linear',
    })
    await upsertCredProfile(db, '/org_abc/linear', {
      host: ['api.linear.org'],
      displayName: 'Org Linear',
    })
    await upsertCredProfile(db, '/org_abc/ws_engineering/linear', {
      host: ['api.linear.engineering'],
      displayName: 'Engineering Linear',
    })
    await upsertCredProfile(db, '/org_abc/ws_design/linear', {
      host: ['api.linear.design'],
      displayName: 'Design Linear',
    })
    await upsertCredProfile(db, '/org_abc/ws_engineering/user_alice/linear', {
      host: ['api.linear.alice'],
      displayName: 'Alice Linear',
    })

    expect(
      (await getCredProfilesBySlugWithPublicFallback(db, 'linear', '/org_abc/ws_engineering'))
        .map(profile => profile.path),
    ).toEqual([
      '/org_abc/ws_engineering/linear',
      '/org_abc/linear',
    ])

    expect(
      (await getCredProfilesBySlugWithPublicFallback(db, 'linear', '/org_abc/ws_engineering/service'))
        .map(profile => profile.path),
    ).toEqual([
      '/org_abc/ws_engineering/linear',
      '/org_abc/linear',
    ])

    expect(
      (await getCredProfilesBySlugWithPublicFallback(db, 'linear', '/org_abc/ws_support'))
        .map(profile => profile.path),
    ).toEqual([
      '/org_abc/linear',
    ])

    expect(
      (await getCredProfilesBySlugWithPublicFallback(db, 'linear', '/org_xyz/ws_support'))
        .map(profile => profile.path),
    ).toEqual([
      '/linear',
    ])
  })

  it('records revocations and manages auth flow lifecycle', async () => {
    await db.execute(sql`set time zone '-08:00'`)

    expect(await isRevoked(db, 'rev-1')).toBe(false)
    await revokeToken(db, 'rev-1', 'user request')
    expect(await isRevoked(db, 'rev-1')).toBe(true)

    await createAuthFlow(db, {
      id: 'flow-near-future',
      method: 'api_key',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    })
    await createAuthFlow(db, {
      id: 'flow-1',
      profilePath: publicProfilePath('github'),
      method: 'oauth',
      codeVerifier: 'verifier',
      scopePath: '/org_alpha',
      expiresAt: new Date('2099-01-01T00:00:00.000Z'),
    })
    await createAuthFlow(db, {
      id: 'flow-expired',
      method: 'api_key',
      expiresAt: new Date('2000-01-01T00:00:00.000Z'),
    })

    expect(await getAuthFlow(db, 'flow-expired')).toBeNull()
    expect(await getAuthFlow(db, 'missing-flow')).toBeNull()
    expect(await getAuthFlow(db, 'flow-near-future')).toEqual(expect.objectContaining({
      id: 'flow-near-future',
      status: 'pending',
      method: 'api_key',
    }))

    expect(await getAuthFlow(db, 'flow-1')).toEqual(expect.objectContaining({
      id: 'flow-1',
      status: 'pending',
      method: 'oauth',
    }))

    await completeAuthFlow(db, 'flow-1', {
      token: 'access-token',
      identity: 'user-123',
    })

    expect(await getAuthFlow(db, 'flow-1')).toEqual(expect.objectContaining({
      id: 'flow-1',
      status: 'completed',
      token: 'access-token',
      identity: 'user-123',
    }))
  })
})
