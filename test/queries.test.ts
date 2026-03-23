import { beforeEach, describe, expect, it } from 'vitest'
import {
  createIssuedToken,
  deleteCredential,
  getCredProfile,
  getCredProfilesByHostWithinRoot,
  getCredProfilesByProviderWithinRoot,
  getCredential,
  getCredentialsByHostWithinRoot,
  getCredentialsByProfileWithinRoot,
  getIssuedTokenByHash,
  getIssuedTokenById,
  getIssuedTokenByIdUnscoped,
  isMissingIssuedTokensTableError,
  isRevoked,
  listCredProfiles,
  listCredentials,
  listIssuedTokensByOwner,
  markIssuedTokenUsed,
  markIssuedTokenUsedBestEffort,
  revokeIssuedTokenById,
  revokeIssuedTokenByIdUnscoped,
  revokeToken,
  upsertCredProfile,
  upsertCredential,
} from 'agent.pw/sql'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '../packages/server/src/lib/credentials-crypto'
import { getRevocationIds, hashToken, mintToken } from 'agent.pw/access'
import { publicProfilePath } from 'agent.pw/paths'
import {
  BISCUIT_PRIVATE_KEY,
  PUBLIC_KEY_HEX,
  createTestDb,
  type TestDb,
} from './setup'

let db: TestDb

async function storeBearerCredential(profilePath: string, host: string, path: string, token: string) {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const secret = await encryptCredentials(encryptionKey, {
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, token),
  })

  await upsertCredential(db, {
    profilePath,
    host,
    path,
    auth: { kind: 'headers' },
    secret,
  })
}

beforeEach(async () => {
  db = await createTestDb()
})

describe('query layer', () => {
  it('resolves credential profiles across the path tree', async () => {
    await upsertCredProfile(db, publicProfilePath('linear'), {
      host: ['api.linear.global'],
      displayName: 'Global Linear',
      oauthConfig: {
        clientId: 'smithery-client',
      },
    })
    await upsertCredProfile(db, '/org_alpha/linear', {
      host: ['api.linear.org'],
      displayName: 'Org Linear',
    })
    await upsertCredProfile(db, '/org_alpha/ws_engineering/linear', {
      host: ['api.linear.engineering'],
      displayName: 'Engineering Linear',
    })
    await upsertCredProfile(db, '/org_alpha/ws_design/linear', {
      host: ['api.linear.design'],
      displayName: 'Design Linear',
    })

    expect(await getCredProfile(db, publicProfilePath('linear'))).toEqual(
      expect.objectContaining({
        path: '/linear',
        oauthConfig: { clientId: 'smithery-client' },
      }),
    )

    expect(
      (await getCredProfilesByProviderWithinRoot(db, 'linear', '/org_alpha/ws_engineering/service'))
        .map(profile => profile.path),
    ).toEqual([
      '/org_alpha/ws_engineering/linear',
      '/org_alpha/linear',
      '/linear',
    ])

    expect(
      (await getCredProfilesByHostWithinRoot(db, 'api.linear.design', '/org_alpha/ws_design/project'))
        .map(profile => profile.path),
    ).toEqual(['/org_alpha/ws_design/linear'])

    expect(
      (await getCredProfilesByHostWithinRoot(db, 'api.linear.global', '/org_beta/service'))
        .map(profile => profile.path),
    ).toEqual(['/linear'])

    expect((await listCredProfiles(db, { root: '/org_alpha' })).map(profile => profile.path)).toEqual([
      '/org_alpha/linear',
      '/org_alpha/ws_design/linear',
      '/org_alpha/ws_engineering/linear',
    ])
  })

  it('handles credential lookups within explicit roots', async () => {
    await storeBearerCredential('/linear', 'api.linear.app', '/root-cred', 'root-token')
    await storeBearerCredential('/linear', 'api.linear.app', '/org_alpha/linear', 'org-token')
    await storeBearerCredential('/linear', 'api.linear.app', '/org_alpha/ws_engineering/linear', 'eng-token')
    await storeBearerCredential('/linear', 'api.linear.app', '/org_beta/linear', 'beta-token')

    expect(await getCredential(db, '/org_alpha/linear')).toEqual(
      expect.objectContaining({ path: '/org_alpha/linear' }),
    )

    expect((await getCredentialsByProfileWithinRoot(db, '/linear', '/org_alpha')).map(row => row.path)).toEqual([
      '/org_alpha/linear',
      '/root-cred',
    ])
    expect((await getCredentialsByHostWithinRoot(db, 'api.linear.app', '/org_alpha')).map(row => row.path)).toEqual([
      '/org_alpha/linear',
      '/root-cred',
    ])

    expect((await listCredentials(db, { root: '/org_alpha' })).map(row => row.path)).toEqual([
      '/org_alpha/linear',
      '/org_alpha/ws_engineering/linear',
    ])

    expect(await deleteCredential(db, '/org_alpha/linear')).toBe(true)
    expect(await deleteCredential(db, '/org_alpha/linear')).toBe(false)
  })

  it('tracks issued tokens by owner, hash, usage, and revocation', async () => {
    const userToken = mintToken(
      BISCUIT_PRIVATE_KEY,
      'user_alpha',
      [{ action: 'credential.use', root: '/org_alpha' }],
      ['org_id("org_alpha")'],
    )
    const orgToken = mintToken(
      BISCUIT_PRIVATE_KEY,
      'org_alpha',
      [{ action: 'credential.manage', root: '/org_alpha' }],
      ['org_id("org_alpha")'],
    )

    const userHash = await hashToken(userToken)
    const orgHash = await hashToken(orgToken)
    const userRevocationIds = getRevocationIds(userToken, PUBLIC_KEY_HEX)
    const orgRevocationIds = getRevocationIds(orgToken, PUBLIC_KEY_HEX)

    await createIssuedToken(db, {
      id: 'tok_user',
      ownerUserId: 'user_alpha',
      orgId: 'org_alpha',
      name: 'User token',
      tokenHash: userHash,
      revocationIds: userRevocationIds,
      rights: [{ action: 'credential.use', root: '/org_alpha' }],
      constraints: [{ methods: 'GET' }],
      expiresAt: new Date('2099-01-01T00:00:00.000Z'),
    })
    await createIssuedToken(db, {
      id: 'tok_org',
      ownerUserId: null,
      orgId: 'org_alpha',
      name: 'Org token',
      tokenHash: orgHash,
      revocationIds: orgRevocationIds,
      rights: [{ action: 'credential.manage', root: '/org_alpha' }],
      constraints: [],
    })

    expect((await listIssuedTokensByOwner(db, {
      ownerUserId: 'user_alpha',
      orgId: 'org_alpha',
    })).map(row => row.id)).toEqual(['tok_user'])
    expect((await listIssuedTokensByOwner(db, {
      ownerUserId: null,
      orgId: 'org_alpha',
    })).map(row => row.id)).toEqual(['tok_org'])

    expect(await getIssuedTokenById(db, 'tok_user', {
      ownerUserId: 'user_alpha',
      orgId: 'org_alpha',
    })).toEqual(expect.objectContaining({ id: 'tok_user' }))
    expect(await getIssuedTokenByIdUnscoped(db, 'tok_org')).toEqual(
      expect.objectContaining({ id: 'tok_org' }),
    )
    expect(await getIssuedTokenByHash(db, userHash)).toEqual(
      expect.objectContaining({ id: 'tok_user' }),
    )

    const usedAt = new Date('2099-02-02T00:00:00.000Z')
    expect(await markIssuedTokenUsed(db, userHash, usedAt)).toEqual(
      expect.objectContaining({ id: 'tok_user', lastUsedAt: usedAt }),
    )
    expect(await markIssuedTokenUsedBestEffort(db, 'missing', usedAt)).toBeNull()

    const revokedByOwner = await revokeIssuedTokenById(db, 'tok_user', {
      ownerUserId: 'user_alpha',
      orgId: 'org_alpha',
    }, 'manual')
    expect(revokedByOwner).toEqual(expect.objectContaining({
      id: 'tok_user',
      revokeReason: 'manual',
    }))
    const userRevocationId = userRevocationIds[0]
    expect(userRevocationId).toBeDefined()
    if (!userRevocationId) {
      throw new Error('Missing user revocation id')
    }
    expect(await isRevoked(db, userRevocationId)).toBe(true)

    const revokedUnscoped = await revokeIssuedTokenByIdUnscoped(db, 'tok_org', 'ops')
    expect(revokedUnscoped).toEqual(expect.objectContaining({
      id: 'tok_org',
      revokeReason: 'ops',
    }))
    const orgRevocationId = orgRevocationIds[0]
    expect(orgRevocationId).toBeDefined()
    if (!orgRevocationId) {
      throw new Error('Missing org revocation id')
    }
    expect(await isRevoked(db, orgRevocationId)).toBe(true)

    expect(await revokeIssuedTokenByIdUnscoped(db, 'missing', 'noop')).toBeNull()
  })

  it('records standalone revocation ids and detects missing issued-token ledgers', async () => {
    expect(await isRevoked(db, 'rev-1')).toBe(false)
    await revokeToken(db, 'rev-1', 'manual')
    expect(await isRevoked(db, 'rev-1')).toBe(true)

    expect(
      isMissingIssuedTokensTableError(
        new Error('relation "agentpw.issued_tokens" does not exist'),
      ),
    ).toBe(true)
    expect(isMissingIssuedTokensTableError(new Error('boom'))).toBe(false)
  })
})
