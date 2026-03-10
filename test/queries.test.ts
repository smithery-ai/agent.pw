import { beforeEach, describe, expect, it } from 'vitest'
import {
  completeAuthFlow,
  createAuthFlow,
  deleteCredential,
  deleteService,
  getAuthFlow,
  getCredProfile,
  getCredProfileByHost,
  getCredProfileByHostForPath,
  getCredential,
  getCredentialsByHost,
  getCredentialsByHostForUsage,
  getService,
  isRevoked,
  listCredProfilesWithCredentialCounts,
  listCredentials,
  listCredentialsAccessible,
  listCredentialsAdminAccessible,
  listServices,
  listServicesWithCredentialCounts,
  revokeToken,
  upsertCredProfile,
  upsertCredential,
  upsertService,
} from '@agent.pw/server/db/queries'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '@agent.pw/server/crypto'
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
  it('handles profile lookups, visibility, and legacy service compatibility', async () => {
    await upsertCredProfile(db, '/global', {
      host: ['api.global.com', 'api.shared.com'],
      displayName: 'Global',
      description: 'root profile',
    })
    await upsertCredProfile(db, '/org_alpha/team/service', {
      host: ['api.team.com'],
      auth: { authSchemes: [{ type: 'http', scheme: 'bearer' }] },
      displayName: 'Team',
    })
    await upsertService(db, '/compat', {
      allowedHosts: ['api.compat.com'],
      authSchemes: [{ type: 'apiKey', in: 'header', name: 'X-Api-Key' }],
      displayName: 'Compat',
      description: 'legacy profile',
      oauthClientId: 'client-id',
      encryptedOauthClientSecret: Buffer.from('secret'),
      docsUrl: 'https://docs.example.com',
      authConfig: { token_auth: 'basic' },
    })
    await upsertService(db, '/plain', {
      allowedHosts: ['api.plain.com'],
    })

    await storeBearerCredential('api.global.com', '/global-cred', 'global-token')
    await storeBearerCredential('api.shared.com', '/shared-cred', 'shared-token')
    await storeBearerCredential('api.compat.com', '/compat-cred', 'compat-token')

    expect(await getCredProfile(db, '/global')).toEqual(expect.objectContaining({ path: '/global' }))
    expect(await getCredProfileByHost(db, 'api.global.com')).toEqual(expect.objectContaining({ path: '/global' }))
    expect(await getCredProfileByHost(db, 'missing.example.com')).toBeNull()
    expect(await getCredProfileByHostForPath(db, 'api.team.com', '/org_alpha')).toEqual(
      expect.objectContaining({ path: '/org_alpha/team/service' }),
    )
    expect(await getCredProfileByHostForPath(db, 'api.team.com', '/org_beta')).toBeNull()

    const countedProfiles = await listCredProfilesWithCredentialCounts(db)
    expect(countedProfiles.find(profile => profile.path === '/global')?.credentialCount).toBe(2)

    const service = await getService(db, '/compat')
    expect(service).toEqual(expect.objectContaining({
      slug: '/compat',
      allowedHosts: '["api.compat.com"]',
      oauthClientId: 'client-id',
      docsUrl: 'https://docs.example.com',
      authConfig: '{"token_auth":"basic"}',
    }))
    expect(JSON.parse(service?.authSchemes ?? '[]')).toEqual([
      { type: 'apiKey', in: 'header', name: 'X-Api-Key' },
    ])

    expect((await listServices(db)).map(service => service.slug)).toEqual(
      expect.arrayContaining(['/global', '/org_alpha/team/service', '/compat', '/plain']),
    )
    expect((await listServicesWithCredentialCounts(db)).find(service => service.slug === '/compat')?.credentialCount).toBe(1)
    expect(await deleteService(db, '/compat')).toBe(true)
    expect(await deleteService(db, '/compat')).toBe(false)
  })

  it('handles credential access queries for admin and usage flows', async () => {
    await storeBearerCredential('api.example.com', '/root-cred', 'root-token')
    await storeBearerCredential('api.example.com', '/org_alpha/org-cred', 'org-token')
    await storeBearerCredential('api.example.com', '/org_alpha/team/team-cred', 'team-token')
    await storeBearerCredential('api.example.com', '/org_beta/other-cred', 'other-token')

    expect(await getCredential(db, 'api.example.com', '/org_alpha/org-cred')).toEqual(
      expect.objectContaining({ path: '/org_alpha/org-cred' }),
    )
    expect((await getCredentialsByHost(db, 'api.example.com')).length).toBe(4)
    expect((await listCredentials(db)).length).toBe(4)

    const adminAccessible = await listCredentialsAdminAccessible(db, '/org_alpha')
    expect(adminAccessible.map(credential => credential.path)).toEqual(
      expect.arrayContaining(['/org_alpha/org-cred', '/org_alpha/team/team-cred']),
    )
    expect(adminAccessible.map(credential => credential.path)).not.toContain('/root-cred')

    const accessible = await listCredentialsAccessible(db, '/org_alpha/team')
    expect(accessible.map(credential => credential.path)).toEqual(
      expect.arrayContaining(['/root-cred', '/org_alpha/org-cred', '/org_alpha/team/team-cred']),
    )
    expect(accessible.map(credential => credential.path)).not.toContain('/org_beta/other-cred')

    expect((await getCredentialsByHostForUsage(db, 'api.example.com', '/org_alpha/team')).map(credential => credential.path)).toEqual([
      '/org_alpha/team/team-cred',
      '/org_alpha/org-cred',
      '/root-cred',
    ])

    expect(await deleteCredential(db, 'api.example.com', '/org_alpha/org-cred')).toBe(true)
    expect(await deleteCredential(db, 'api.example.com', '/org_alpha/org-cred')).toBe(false)
  })

  it('records revocations and manages auth flow lifecycle', async () => {
    expect(await isRevoked(db, 'rev-1')).toBe(false)
    await revokeToken(db, 'rev-1', 'user request')
    expect(await isRevoked(db, 'rev-1')).toBe(true)

    await createAuthFlow(db, {
      id: 'flow-1',
      profilePath: '/github',
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
