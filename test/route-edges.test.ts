import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCoreApp } from '@agent.pw/server'
import { decryptCredentials, deriveEncryptionKey } from '@agent.pw/server/crypto'
import * as biscuitModule from '@agent.pw/server/biscuit'
import * as queryModule from '@agent.pw/server/db/queries'
import {
  getCredential,
  upsertCredProfile,
} from '@agent.pw/server/db/queries'
import {
  BISCUIT_PRIVATE_KEY,
  ROOT_TOKEN,
  PUBLIC_KEY_HEX,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'

let db: TestDb
let app: ReturnType<typeof createCoreApp>

beforeEach(async () => {
  db = await createTestDb()
  app = createCoreApp({
    db,
    biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    baseUrl: 'https://agent.pw',
    cliAuthBaseUrl: 'https://agent.pw',
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

function withToken(token: string, headers: Record<string, string> = {}) {
  return { 'Proxy-Authorization': `Bearer ${token}`, ...headers }
}

describe('route edge cases', () => {
  it('validates credential writes and derives hosts from profiles', async () => {
    const token = mintTestToken('org_alpha')

    const missingSecret = await app.request('https://agent.pw/credentials/github', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: 'api.github.com' }),
    })
    expect(missingSecret.status).toBe(400)

    const invalidName = await app.request('https://agent.pw/credentials/a.b', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret', host: 'api.github.com' }),
    })
    expect(invalidName.status).toBe(400)

    const badPath = await app.request('https://agent.pw/credentials/github', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret', host: 'api.github.com', path: '/' }),
    })
    expect(badPath.status).toBe(400)

    const nameMismatch = await app.request('https://agent.pw/credentials/github', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret', host: 'api.github.com', path: '/orgs/org_alpha/gitlab' }),
    })
    expect(nameMismatch.status).toBe(400)

    const missingProfile = await app.request('https://agent.pw/credentials/github', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret' }),
    })
    expect(missingProfile.status).toBe(404)

    await upsertCredProfile(db, '/oauth-only', {
      host: ['api.oauth-only.com'],
      auth: { kind: 'oauth' },
    })
    const oauthCredential = await app.request('https://agent.pw/credentials/oauth-only', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'oauth-secret', profile: 'oauth-only' }),
    })
    expect(oauthCredential.status).toBe(200)

    await upsertCredProfile(db, '/empty-host', {
      host: [],
    })
    const missingHost = await app.request('https://agent.pw/credentials/empty-host', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret', profile: 'empty-host' }),
    })
    expect(missingHost.status).toBe(400)

    await upsertCredProfile(db, '/api-key', {
      host: ['api.keys.example'],
      auth: { authSchemes: [{ type: 'apiKey', in: 'header', name: 'X-Api-Key' }] },
    })
    const apiKeyCredential = await app.request('https://agent.pw/credentials/api-key', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'key-secret', profile: 'api-key' }),
    })
    expect(apiKeyCredential.status).toBe(200)

    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const storedApiKey = await getCredential(db, 'api.keys.example', '/orgs/org_alpha/api-key')
    expect(await decryptCredentials(encryptionKey, storedApiKey!.secret)).toEqual({
      headers: { 'X-Api-Key': 'key-secret' },
    })
  })

  it('validates credential deletes across query combinations', async () => {
    const token = mintTestToken('org_alpha')

    const invalidName = await app.request('https://agent.pw/credentials/a.b', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(invalidName.status).toBe(400)

    const invalidPath = await app.request('https://agent.pw/credentials/github?host=api.github.com&path=%2F', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(invalidPath.status).toBe(400)

    const mismatchPath = await app.request('https://agent.pw/credentials/github?host=api.github.com&path=%2Forgs%2Forg_alpha%2Fgitlab', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(mismatchPath.status).toBe(400)

    const missingHost = await app.request('https://agent.pw/credentials/github', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(missingHost.status).toBe(400)

    const missingDeleteProfile = await app.request('https://agent.pw/credentials/github?profile=missing', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(missingDeleteProfile.status).toBe(404)

    await upsertCredProfile(db, '/empty-delete', {
      host: [],
    })
    const emptyProfileHost = await app.request('https://agent.pw/credentials/empty-delete?profile=empty-delete', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(emptyProfileHost.status).toBe(400)

    await upsertCredProfile(db, '/delete-me', {
      host: ['api.delete.me'],
    })
    const missingCredential = await app.request('https://agent.pw/credentials/delete-me?profile=delete-me', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(missingCredential.status).toBe(404)

    const created = await app.request('https://agent.pw/credentials/race-delete', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ token: 'secret', host: 'api.github.com' }),
    })
    expect(created.status).toBe(200)

    vi.spyOn(queryModule, 'deleteCredential').mockResolvedValueOnce(false)
    const lostDeleteRace = await app.request('https://agent.pw/credentials/race-delete?host=api.github.com', {
      method: 'DELETE',
      headers: withToken(token),
    })
    expect(lostDeleteRace.status).toBe(404)
  })

  it('supports profile reads and profile mutation edge cases', async () => {
    const manager = mintTestToken('org_alpha', ['manage_services'])

    await upsertCredProfile(db, '/visible', {
      host: ['api.visible.com'],
      auth: { kind: 'headers' },
      displayName: 'Visible',
    })

    const detail = await app.request('https://agent.pw/cred_profiles/visible', {
      headers: withToken(ROOT_TOKEN),
    })
    expect(detail.status).toBe(200)
    expect(await detail.json()).toEqual({
      slug: '/visible',
      host: ['api.visible.com'],
      path: '/visible',
      displayName: 'Visible',
      description: null,
      auth: { kind: 'headers' },
    })

    await upsertCredProfile(db, '/no-auth', {
      host: ['api.no-auth.com'],
    })
    const detailWithoutAuth = await app.request('https://agent.pw/cred_profiles/no-auth', {
      headers: withToken(ROOT_TOKEN),
    })
    expect(detailWithoutAuth.status).toBe(200)
    expect(await detailWithoutAuth.json()).toEqual({
      slug: '/no-auth',
      host: ['api.no-auth.com'],
      path: '/no-auth',
      displayName: null,
      description: null,
      auth: null,
    })

    const missing = await app.request('https://agent.pw/cred_profiles/missing', {
      headers: withToken(ROOT_TOKEN),
    })
    expect(missing.status).toBe(404)

    const invalidPath = await app.request('https://agent.pw/cred_profiles/bad-path', {
      method: 'PUT',
      headers: withToken(manager, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: ['api.bad.com'], path: 'invalid' }),
    })
    expect(invalidPath.status).toBe(400)

    const reserved = await app.request('https://agent.pw/cred_profiles/auth', {
      method: 'PUT',
      headers: withToken(manager, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: ['api.auth.com'] }),
    })
    expect(reserved.status).toBe(400)

    await upsertCredProfile(db, '/root-svc', {
      host: ['api.root.com'],
    })
    const forbiddenUpdate = await app.request('https://agent.pw/cred_profiles/root-svc', {
      method: 'PUT',
      headers: withToken(manager, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: ['api.org.com'] }),
    })
    expect(forbiddenUpdate.status).toBe(403)

    const missingDelete = await app.request('https://agent.pw/cred_profiles/missing', {
      method: 'DELETE',
      headers: withToken(manager),
    })
    expect(missingDelete.status).toBe(404)

    const forbiddenDelete = await app.request('https://agent.pw/cred_profiles/root-svc', {
      method: 'DELETE',
      headers: withToken(manager),
    })
    expect(forbiddenDelete.status).toBe(403)

    const deleteOwn = await app.request('https://agent.pw/cred_profiles/owned', {
      method: 'PUT',
      headers: withToken(ROOT_TOKEN, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: ['api.owned.com'] }),
    })
    expect(deleteOwn.status).toBe(200)

    const deleted = await app.request('https://agent.pw/cred_profiles/owned', {
      method: 'DELETE',
      headers: withToken(ROOT_TOKEN),
    })
    expect(deleted.status).toBe(200)

    const createRace = await app.request('https://agent.pw/cred_profiles/race-profile', {
      method: 'PUT',
      headers: withToken(ROOT_TOKEN, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ host: ['api.race.com'] }),
    })
    expect(createRace.status).toBe(200)

    vi.spyOn(queryModule, 'deleteCredProfile').mockResolvedValueOnce(false)
    const lostDeleteRace = await app.request('https://agent.pw/cred_profiles/race-profile', {
      method: 'DELETE',
      headers: withToken(ROOT_TOKEN),
    })
    expect(lostDeleteRace.status).toBe(404)
  })

  it('rejects malformed pagination cursors on credentials and profiles', async () => {
    const token = mintTestToken('org_alpha')

    const badCredCursor = await app.request('https://agent.pw/credentials?cursor=bad-cursor', {
      headers: withToken(token),
    })
    expect(badCredCursor.status).toBe(400)
    expect(await badCredCursor.json()).toEqual({ error: 'Invalid pagination cursor' })

    const badProfileCursor = await app.request('https://agent.pw/cred_profiles?cursor=bad-cursor', {
      headers: withToken(token),
    })
    expect(badProfileCursor.status).toBe(400)
    expect(await badProfileCursor.json()).toEqual({ error: 'Invalid pagination cursor' })
  })

  it('paginates credentials and profiles with cursor continuation', async () => {
    const manager = mintTestToken('org_alpha', ['manage_services'])
    const token = mintTestToken('org_alpha')

    // Create two profiles for pagination
    for (const slug of ['aaa-svc', 'bbb-svc']) {
      await app.request(`https://agent.pw/cred_profiles/${slug}`, {
        method: 'PUT',
        headers: withToken(manager, { 'Content-Type': 'application/json' }),
        body: JSON.stringify({ host: [`api.${slug}.com`] }),
      })
    }

    const firstProfilePage = await app.request('https://agent.pw/cred_profiles?limit=1', {
      headers: withToken(token),
    })
    expect(firstProfilePage.status).toBe(200)
    const profilePage = await firstProfilePage.json() as { data: unknown[]; hasMore: boolean; nextCursor: string | null }
    expect(profilePage.data).toHaveLength(1)
    expect(profilePage.hasMore).toBe(true)
    expect(profilePage.nextCursor).toBeTruthy()

    const secondProfilePage = await app.request(`https://agent.pw/cred_profiles?limit=1&cursor=${profilePage.nextCursor}`, {
      headers: withToken(token),
    })
    expect(secondProfilePage.status).toBe(200)
    const page2 = await secondProfilePage.json() as { data: unknown[]; hasMore: boolean; nextCursor: string | null }
    expect(page2.data).toHaveLength(1)
    expect(page2.hasMore).toBe(false)

    // Create two credentials with same host for host comparison coverage
    for (const name of ['cred-aaa', 'cred-bbb']) {
      await app.request(`https://agent.pw/credentials/${name}`, {
        method: 'PUT',
        headers: withToken(token, { 'Content-Type': 'application/json' }),
        body: JSON.stringify({ token: `secret-${name}`, host: 'api.same-host.com' }),
      })
    }

    const firstCredPage = await app.request('https://agent.pw/credentials?limit=1', {
      headers: withToken(token),
    })
    expect(firstCredPage.status).toBe(200)
    const credPage = await firstCredPage.json() as { data: unknown[]; hasMore: boolean; nextCursor: string | null }
    expect(credPage.data).toHaveLength(1)
    expect(credPage.hasMore).toBe(true)
    expect(credPage.nextCursor).toBeTruthy()

    const secondCredPage = await app.request(`https://agent.pw/credentials?limit=1&cursor=${credPage.nextCursor}`, {
      headers: withToken(token),
    })
    expect(secondCredPage.status).toBe(200)
    const credPage2 = await secondCredPage.json() as { data: unknown[]; hasMore: boolean; nextCursor: string | null }
    expect(credPage2.data).toHaveLength(1)
    expect(credPage2.hasMore).toBe(false)
  })

  it('re-throws non-pagination errors from list endpoints', async () => {
    const paginationModule = await import('../packages/server/src/lib/pagination')
    const token = mintTestToken('org_alpha')

    const spy = vi.spyOn(paginationModule, 'paginateItems').mockImplementation(() => {
      throw new Error('unexpected error')
    })

    const credRes = await app.request('https://agent.pw/credentials', {
      headers: withToken(token),
    })
    expect(credRes.status).toBe(500)

    const profileRes = await app.request('https://agent.pw/cred_profiles', {
      headers: withToken(token),
    })
    expect(profileRes.status).toBe(500)

    spy.mockRestore()
  })

  it('surfaces token route failures as 400 responses', async () => {
    const token = mintTestToken('org_alpha')

    const badRestrict = await app.request('https://agent.pw/tokens/restrict', {
      method: 'POST',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        constraints: [{ ttl: 'later' }],
      }),
    })
    expect(badRestrict.status).toBe(400)

    const originalGetRevocationIds = biscuitModule.getRevocationIds
    const revocationSpy = vi.spyOn(biscuitModule, 'getRevocationIds')
    revocationSpy
      .mockImplementationOnce(originalGetRevocationIds)
      .mockImplementationOnce(() => {
        throw new Error('revocation lookup failed')
      })

    const badRevoke = await app.request('https://agent.pw/tokens/revoke', {
      method: 'POST',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({ reason: 'testing' }),
    })
    expect(badRevoke.status).toBe(400)
    expect(await badRevoke.json()).toEqual({
      error: 'Failed to revoke token: revocation lookup failed',
    })
  })
})
