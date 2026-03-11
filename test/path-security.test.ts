import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createCoreApp } from '@agent.pw/server'
import {
  BISCUIT_PRIVATE_KEY,
  createTestDb,
  mintTestToken,
  type TestDb,
} from './setup'
import {
  revokeToken as revokeTokenById,
  upsertCredProfile,
  upsertCredential,
} from '@agent.pw/server/db/queries'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '@agent.pw/server/crypto'
import {
  credentialName,
  credentialParentPath,
  deepestAncestor,
  isAncestorOrEqual,
  joinCredentialPath,
  pathDepth,
  pathFromTokenFacts,
  publicProfilePath,
  validateCredentialName,
  validatePath,
} from '@agent.pw/server/paths'
import { getPublicKeyHex, getRevocationIds, restrictToken } from '@agent.pw/server/biscuit'

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
  vi.unstubAllGlobals()
})

function req(path: string, init?: RequestInit) {
  return app.request(`https://agent.pw${path}`, init)
}

function withToken(token: string, headers: Record<string, string> = {}) {
  return { 'Proxy-Authorization': `Bearer ${token}`, ...headers }
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockUpstream(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>,
) {
  const fetchMock = vi.fn(handler)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function storeCredentialAtPath(
  name: string,
  host: string,
  tokenValue: string,
  basePath: string,
) {
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const encrypted = await encryptCredentials(encryptionKey, {
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, tokenValue),
  })

  const path = basePath === '/' ? `/${name}` : `${basePath}/${name}`
  await upsertCredential(db, {
    host,
    path,
    auth: { kind: 'headers' },
    secret: encrypted,
  })
}

const ORG_A = 'org_alpha'
const ORG_B = 'org_beta'

describe('isAncestorOrEqual', () => {
  it('treats root as ancestor of everything and handles exact matches', () => {
    expect(isAncestorOrEqual('/', '/a')).toBe(true)
    expect(isAncestorOrEqual('/', '/')).toBe(true)
    expect(isAncestorOrEqual('/a', '/a')).toBe(true)
  })

  it('matches direct and indirect descendants only on path boundaries', () => {
    expect(isAncestorOrEqual('/a', '/a/ws/eng')).toBe(true)
    expect(isAncestorOrEqual('/a', '/a/ws/eng/team/1')).toBe(true)
    expect(isAncestorOrEqual('/a/', '/a/ws/eng')).toBe(true)
    expect(isAncestorOrEqual('/ab', '/abc')).toBe(false)
    expect(isAncestorOrEqual('/ab', '/abd')).toBe(false)
  })

  it('does not treat descendants or siblings as ancestors', () => {
    expect(isAncestorOrEqual('/a/ws/eng', '/a')).toBe(false)
    expect(isAncestorOrEqual('/a', '/b')).toBe(false)
    expect(isAncestorOrEqual('/a/ws/eng', '/a/ws/sales')).toBe(false)
  })
})

describe('pathFromTokenFacts', () => {
  it('derives org-rooted paths and falls back to root', () => {
    expect(pathFromTokenFacts({ orgId: 'ruzo' })).toBe('/ruzo')
    expect(pathFromTokenFacts({})).toBe('/')
    expect(pathFromTokenFacts({ orgId: null })).toBe('/')
  })
})

describe('validatePath', () => {
  it('accepts canonical paths and rejects traversal or malformed values', () => {
    expect(validatePath('/')).toBe(true)
    expect(validatePath('/a')).toBe(true)
    expect(validatePath('/a/ws/eng')).toBe(true)
    expect(validatePath('a/b')).toBe(false)
    expect(validatePath('')).toBe(false)
    expect(validatePath('/a/')).toBe(false)
    expect(validatePath('/../etc')).toBe(false)
    expect(validatePath('/a/../../')).toBe(false)
  })
})

describe('deepestAncestor', () => {
  it('returns the deepest matching ancestor and null when none match', () => {
    const candidates = [
      { path: '/', name: 'root' },
      { path: '/a', name: 'org' },
      { path: '/a/ws/eng', name: 'workspace' },
    ]

    expect(deepestAncestor(candidates, '/a/ws/eng/team/1')?.name).toBe('workspace')
    expect(deepestAncestor([{ path: '/b', name: 'other' }], '/a')).toBeNull()
  })

  it('prefers exact matches over shallower ancestors', () => {
    const candidates = [
      { path: '/a', name: 'org' },
      { path: '/a/ws/eng', name: 'exact' },
    ]

    expect(deepestAncestor(candidates, '/a/ws/eng')?.name).toBe('exact')
  })
})

describe('credential path helpers', () => {
  it('builds and inspects credential paths consistently', () => {
    expect(joinCredentialPath('/', 'github')).toBe('/github')
    expect(joinCredentialPath('/a', 'github')).toBe('/a/github')
    expect(credentialParentPath('/github')).toBe('/')
    expect(credentialParentPath('/a/github')).toBe('/a')
    expect(credentialName('/a/github')).toBe('github')
    expect(pathDepth('/')).toBe(0)
    expect(pathDepth('/a/github')).toBe(2)
  })

  it('validates credential names', () => {
    expect(validateCredentialName('github')).toBe(true)
    expect(validateCredentialName('')).toBe(false)
    expect(validateCredentialName('a/b')).toBe(false)
    expect(validateCredentialName('..')).toBe(false)
  })
})

describe('cross-org isolation', () => {
  it('keeps list visibility and mutation scoped to the caller org', async () => {
    await storeCredentialAtPath('cred-a', 'api.example.com', 'secret-a', `/${ORG_A}`)
    await storeCredentialAtPath('cred-b', 'api.example.com', 'secret-b', `/${ORG_B}`)

    const tokenA = mintTestToken(ORG_A)

    const list = await req('/credentials', { headers: withToken(tokenA) })
    expect(list.status).toBe(200)
    expect(((await list.json()) as { data: { name: string }[] }).data).toEqual([
      expect.objectContaining({ name: 'cred-a' }),
    ])

    const update = await req('/credentials/cred-b', {
      method: 'PUT',
      headers: withToken(tokenA, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'new-secret',
        host: 'api.example.com',
        path: `/${ORG_B}/cred-b`,
      }),
    })
    expect(update.status).toBe(403)

    const remove = await req(`/credentials/cred-b?host=api.example.com&path=${encodeURIComponent(`/${ORG_B}/cred-b`)}`, {
      method: 'DELETE',
      headers: withToken(tokenA),
    })
    expect(remove.status).toBe(403)
  })

  it('does not let one org proxy or explicitly select another org credential', async () => {
    await storeCredentialAtPath('cred-b', 'api.example.com', 'secret-b', `/${ORG_B}`)
    const tokenA = mintTestToken(ORG_A)

    mockUpstream(() => jsonResponse({ ok: true }))

    const implicit = await req('/proxy/api.example.com/test', {
      headers: withToken(tokenA),
    })
    expect(implicit.status).toBe(200)

    const explicit = await req('/proxy/api.example.com/test', {
      headers: withToken(tokenA, { 'agentpw-credential': 'cred-b' }),
    })
    expect(explicit.status).toBe(404)
  })
})

describe('credential use within descendant roots', () => {
  it('uses credentials inside the granted root and ignores credentials above it', async () => {
    await storeCredentialAtPath('org-cred', 'api.example.com', 'org-secret', `/${ORG_A}`)
    await storeCredentialAtPath('global-cred', 'api.global.com', 'global-secret', '/')
    const token = mintTestToken(ORG_A)

    mockUpstream((_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ auth: headers.get('Authorization') })
    })

    const orgRes = await req('/proxy/api.example.com/test', { headers: withToken(token) })
    expect(orgRes.status).toBe(200)
    expect(await orgRes.json()).toEqual({ auth: 'Bearer org-secret' })

    const rootRes = await req('/proxy/api.global.com/test', { headers: withToken(token) })
    expect(rootRes.status).toBe(200)
    expect(await rootRes.json()).toEqual({ auth: null })
  })

  it('allows a broader right to select a narrower active root and keeps sibling credentials out', async () => {
    await storeCredentialAtPath('github_main', 'api.github.com', 'root-shared-secret', '/org_ruzo/shared')
    await storeCredentialAtPath('github_eng', 'api.github.com', 'engineering-shared-secret', '/org_ruzo/ws_engineering/shared')
    await storeCredentialAtPath('github_personal', 'api.github.com', 'engineering-personal-secret', '/org_ruzo/ws_engineering/user_alice')
    await storeCredentialAtPath('github_design', 'api.github.com', 'design-shared-secret', '/org_ruzo/ws_design/shared')

    mockUpstream((_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ auth: headers.get('Authorization') })
    })

    const token = mintTestToken('org_ruzo', ['credential.use'], ['/org_ruzo/ws_engineering'])

    const sharedRoot = await req('/proxy/api.github.com/user', {
      headers: withToken(token, { 'agentpw-path': '/org_ruzo/ws_engineering/shared' }),
    })
    expect(sharedRoot.status).toBe(200)
    expect(await sharedRoot.json()).toEqual({ auth: 'Bearer engineering-shared-secret' })

    const personalRoot = await req('/proxy/api.github.com/user', {
      headers: withToken(token, { 'agentpw-path': '/org_ruzo/ws_engineering/user_alice' }),
    })
    expect(personalRoot.status).toBe(200)
    expect(await personalRoot.json()).toEqual({ auth: 'Bearer engineering-personal-secret' })

    const wrongSelector = await req('/proxy/api.github.com/user', {
      headers: withToken(token, {
        'agentpw-path': '/org_ruzo/ws_engineering/shared',
        'agentpw-credential': '/org_ruzo/ws_engineering/user_alice/github_personal',
      }),
    })
    expect(wrongSelector.status).toBe(403)
    expect(await wrongSelector.json()).toEqual({
      error: "Token cannot use credential '/org_ruzo/ws_engineering/user_alice/github_personal'",
    })
  })
})

describe('credential management within descendant roots', () => {
  it('lists and deletes descendant credentials but not ancestors', async () => {
    await storeCredentialAtPath('ws-cred', 'api.example.com', 'ws-secret', `/${ORG_A}/ws/eng`)
    await storeCredentialAtPath('root-cred', 'api.example.com', 'root-secret', '/')

    const orgToken = mintTestToken(ORG_A, ['credential.use', 'credential.manage'])

    const list = await req('/credentials', { headers: withToken(orgToken) })
    expect(list.status).toBe(200)
    const names = ((await list.json()) as { data: { name: string }[] }).data.map(credential => credential.name)
    expect(names).toContain('ws-cred')
    expect(names).not.toContain('root-cred')

    const deleteDescendant = await req(`/credentials/ws-cred?host=api.example.com&path=${encodeURIComponent(`/${ORG_A}/ws/eng/ws-cred`)}`, {
      method: 'DELETE',
      headers: withToken(orgToken),
    })
    expect(deleteDescendant.status).toBe(200)

    const deleteAncestor = await req(`/credentials/root-cred?host=api.example.com&path=${encodeURIComponent('/root-cred')}`, {
      method: 'DELETE',
      headers: withToken(orgToken),
    })
    expect(deleteAncestor.status).toBe(403)
  })
})

describe('creation at own path or deeper', () => {
  it('allows creation at the caller path or deeper and blocks creation above it', async () => {
    const token = mintTestToken(ORG_A, ['credential.bootstrap'])

    const ownPath = await req('/credentials/new-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: `/${ORG_A}/new-cred`,
      }),
    })
    expect(ownPath.status).toBe(200)

    const deeper = await req('/credentials/deep-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: `/${ORG_A}/ws/eng/deep-cred`,
      }),
    })
    expect(deeper.status).toBe(200)

    const root = await req('/credentials/root-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: '/root-cred',
      }),
    })
    expect(root.status).toBe(403)

    const otherOrg = await req('/credentials/other-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: `/${ORG_B}/other-cred`,
      }),
    })
    expect(otherOrg.status).toBe(403)

    const invalid = await req('/credentials/bad-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: 'no-leading-slash',
      }),
    })
    expect(invalid.status).toBe(400)
  })

  it('does not treat profile management as credential bootstrap authority', async () => {
    const token = mintTestToken(ORG_A, ['profile.manage'])

    const response = await req('/credentials/github', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.github.com',
        path: `/${ORG_A}/github`,
      }),
    })

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({
      error: `Forbidden: requires "credential.bootstrap" for '/${ORG_A}/github'`,
    })
  })
})

describe('profile resolution', () => {
  it('chooses the nearest visible profile for a host', async () => {
    await upsertCredProfile(db, publicProfilePath('github-global'), {
      host: ['api.github.com'],
      displayName: 'GitHub Global',
      auth: { kind: 'headers', authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await upsertCredProfile(db, `/${ORG_A}/github-org`, {
      host: ['api.github.com'],
      displayName: 'GitHub Org Override',
      auth: { kind: 'headers', authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await storeCredentialAtPath('gh-cred', 'api.github.com', 'gh-secret', `/${ORG_A}`)

    mockUpstream((_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ auth: headers.get('Authorization') })
    })

    const res = await req('/proxy/api.github.com/user', {
      headers: withToken(mintTestToken(ORG_A)),
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ auth: 'Bearer gh-secret' })
  })
})

describe('credential selection semantics', () => {
  it('prefers the deepest ancestor credential and returns conflicts for same-depth matches', async () => {
    await storeCredentialAtPath('global-gh', 'api.github.com', 'global-token', '/')
    await storeCredentialAtPath('org-gh', 'api.github.com', 'org-token', `/${ORG_A}`)
    await storeCredentialAtPath('slack-1', 'slack.com', 'xoxb-1', `/${ORG_A}`)
    await storeCredentialAtPath('slack-2', 'slack.com', 'xoxb-2', `/${ORG_A}`)

    mockUpstream((_input, init) => {
      const headers = new Headers(init?.headers)
      return jsonResponse({ auth: headers.get('Authorization') })
    })

    const token = mintTestToken(ORG_A)

    const deepest = await req('/proxy/api.github.com/test', { headers: withToken(token) })
    expect(deepest.status).toBe(200)
    expect(await deepest.json()).toEqual({ auth: 'Bearer org-token' })

    const conflict = await req('/proxy/slack.com/api/test', { headers: withToken(token) })
    expect(conflict.status).toBe(409)
    expect(await conflict.json()).toEqual(expect.objectContaining({
      credentialNames: expect.arrayContaining(['slack-1', 'slack-2']),
    }))
  })

  it('does not allow partial-segment matches across org boundaries', async () => {
    await storeCredentialAtPath('partial-cred', 'api.example.com', 'secret', '/ab')

    mockUpstream(() => jsonResponse({ ok: true }))

    const res = await req('/proxy/api.example.com/test', {
      headers: withToken(mintTestToken('abc'), { 'agentpw-credential': 'partial-cred' }),
    })
    expect(res.status).toBe(404)
  })
})

describe('token revocation', () => {
  it('rejects a token once any of its revocation ids are stored', async () => {
    const token = mintTestToken(ORG_A)
    await storeCredentialAtPath('cred', 'api.example.com', 'secret', `/${ORG_A}`)

    mockUpstream(() => jsonResponse({ ok: true }))

    const first = await req('/proxy/api.example.com/test', {
      headers: withToken(token),
    })
    expect(first.status).toBe(200)

    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    for (const revocationId of getRevocationIds(token, publicKey)) {
      await revokeTokenById(db, revocationId)
    }

    const second = await req('/proxy/api.example.com/test', {
      headers: withToken(token),
    })
    expect(second.status).toBe(403)
    expect(await second.json()).toEqual({ error: 'Token has been revoked' })
  })

  it('revokes a child branch without affecting siblings until the authority id is revoked', async () => {
    const parent = mintTestToken(ORG_A)
    const publicKey = getPublicKeyHex(BISCUIT_PRIVATE_KEY)
    const childA = restrictToken(parent, publicKey, [{ services: 'api.example.com' }])
    const childB = restrictToken(parent, publicKey, [{ services: 'api.example.com', methods: 'GET' }])

    await storeCredentialAtPath('cred', 'api.example.com', 'secret', `/${ORG_A}`)
    mockUpstream(() => jsonResponse({ ok: true }))

    const parentOk = await req('/proxy/api.example.com/test', {
      headers: withToken(parent),
    })
    expect(parentOk.status).toBe(200)

    const childAOk = await req('/proxy/api.example.com/test', {
      headers: withToken(childA),
    })
    expect(childAOk.status).toBe(200)

    const childBOk = await req('/proxy/api.example.com/test', {
      headers: withToken(childB),
    })
    expect(childBOk.status).toBe(200)

    const childARevocationId = getRevocationIds(childA, publicKey)[1]
    expect(childARevocationId).toBeTruthy()
    await revokeTokenById(db, childARevocationId)

    const parentAfterChildRevoke = await req('/proxy/api.example.com/test', {
      headers: withToken(parent),
    })
    expect(parentAfterChildRevoke.status).toBe(200)

    const childAAfterRevoke = await req('/proxy/api.example.com/test', {
      headers: withToken(childA),
    })
    expect(childAAfterRevoke.status).toBe(403)
    expect(await childAAfterRevoke.json()).toEqual({ error: 'Token has been revoked' })

    const childBAfterSiblingRevoke = await req('/proxy/api.example.com/test', {
      headers: withToken(childB),
    })
    expect(childBAfterSiblingRevoke.status).toBe(200)

    await revokeTokenById(db, getRevocationIds(parent, publicKey)[0])

    const parentAfterAuthorityRevoke = await req('/proxy/api.example.com/test', {
      headers: withToken(parent),
    })
    expect(parentAfterAuthorityRevoke.status).toBe(403)

    const childBAfterAuthorityRevoke = await req('/proxy/api.example.com/test', {
      headers: withToken(childB),
    })
    expect(childBAfterAuthorityRevoke.status).toBe(403)
    expect(await childBAfterAuthorityRevoke.json()).toEqual({ error: 'Token has been revoked' })
  })
})

describe('credential profile path-based access control', () => {
  it('allows profile creation at the caller path and blocks creation above it', async () => {
    const token = mintTestToken(ORG_A, ['profile.manage'])

    const allowed = await req('/cred_profiles/my-service', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        host: ['api.myservice.com'],
        auth: { kind: 'headers' },
      }),
    })
    expect(allowed.status).toBe(200)

    const blocked = await req('/cred_profiles/root-service', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        host: ['api.root.com'],
        path: '/root-service',
        auth: { kind: 'headers' },
      }),
    })
    expect(blocked.status).toBe(403)
  })

  it('lists only profiles inside granted descendant roots', async () => {
    await upsertCredProfile(db, publicProfilePath('global-svc'), {
      host: ['api.global.com'],
      displayName: 'Global',
    })
    await upsertCredProfile(db, `/${ORG_A}/org-svc`, {
      host: ['api.org.com'],
      displayName: 'Org',
    })
    await upsertCredProfile(db, `/${ORG_B}/other-org-svc`, {
      host: ['api.other.com'],
      displayName: 'Other Org',
    })

    const token = mintTestToken(ORG_A)
    const res = await req('/cred_profiles', { headers: withToken(token) })
    expect(res.status).toBe(200)

    const paths = ((await res.json()) as { data: { path: string }[] }).data.map(profile => profile.path)
    expect(paths).toContain(`/${ORG_A}/org-svc`)
    expect(paths).not.toContain(publicProfilePath('global-svc'))
    expect(paths).not.toContain(`/${ORG_B}/other-org-svc`)
  })
})
