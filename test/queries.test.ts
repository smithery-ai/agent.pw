import { beforeEach, describe, expect, it } from 'vitest'
import {
  deleteCredential,
  getCredProfile,
  getCredProfilesByHostWithinRoot,
  getCredProfilesByProviderWithinRoot,
  getCredential,
  getCredentialsByHostWithinRoot,
  getCredentialsByProfileWithinRoot,
  listCredProfiles,
  listCredentials,
  upsertCredProfile,
  upsertCredential,
} from 'agent.pw/sql'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '../packages/server/src/lib/credentials-crypto'
import { publicProfilePath } from 'agent.pw/paths'
import {
  BISCUIT_PRIVATE_KEY,
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
})
