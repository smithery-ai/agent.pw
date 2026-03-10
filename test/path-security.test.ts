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
  validateCredentialName,
  validatePath,
} from '@agent.pw/server/paths'
import { getPublicKeyHex, getRevocationIds } from '@agent.pw/server/biscuit'

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
    expect(isAncestorOrEqual('/', '/orgs/a')).toBe(true)
    expect(isAncestorOrEqual('/', '/')).toBe(true)
    expect(isAncestorOrEqual('/orgs/a', '/orgs/a')).toBe(true)
  })

  it('matches direct and indirect descendants only on path boundaries', () => {
    expect(isAncestorOrEqual('/orgs/a', '/orgs/a/ws/eng')).toBe(true)
    expect(isAncestorOrEqual('/orgs/a', '/orgs/a/ws/eng/team/1')).toBe(true)
    expect(isAncestorOrEqual('/orgs/a/', '/orgs/a/ws/eng')).toBe(true)
    expect(isAncestorOrEqual('/orgs/ab', '/orgs/abc')).toBe(false)
    expect(isAncestorOrEqual('/orgs/ab', '/orgs/abd')).toBe(false)
  })

  it('does not treat descendants or siblings as ancestors', () => {
    expect(isAncestorOrEqual('/orgs/a/ws/eng', '/orgs/a')).toBe(false)
    expect(isAncestorOrEqual('/orgs/a', '/orgs/b')).toBe(false)
    expect(isAncestorOrEqual('/orgs/a/ws/eng', '/orgs/a/ws/sales')).toBe(false)
  })
})

describe('pathFromTokenFacts', () => {
  it('derives org-rooted paths and falls back to root', () => {
    expect(pathFromTokenFacts({ orgId: 'ruzo' })).toBe('/orgs/ruzo')
    expect(pathFromTokenFacts({})).toBe('/')
    expect(pathFromTokenFacts({ orgId: null })).toBe('/')
  })
})

describe('validatePath', () => {
  it('accepts canonical paths and rejects traversal or malformed values', () => {
    expect(validatePath('/')).toBe(true)
    expect(validatePath('/orgs/a')).toBe(true)
    expect(validatePath('/orgs/a/ws/eng')).toBe(true)
    expect(validatePath('orgs/a')).toBe(false)
    expect(validatePath('')).toBe(false)
    expect(validatePath('/orgs/a/')).toBe(false)
    expect(validatePath('/orgs/../etc')).toBe(false)
    expect(validatePath('/orgs/a/../../')).toBe(false)
  })
})

describe('deepestAncestor', () => {
  it('returns the deepest matching ancestor and null when none match', () => {
    const candidates = [
      { path: '/', name: 'root' },
      { path: '/orgs/a', name: 'org' },
      { path: '/orgs/a/ws/eng', name: 'workspace' },
    ]

    expect(deepestAncestor(candidates, '/orgs/a/ws/eng/team/1')?.name).toBe('workspace')
    expect(deepestAncestor([{ path: '/orgs/b', name: 'other' }], '/orgs/a')).toBeNull()
  })

  it('prefers exact matches over shallower ancestors', () => {
    const candidates = [
      { path: '/orgs/a', name: 'org' },
      { path: '/orgs/a/ws/eng', name: 'exact' },
    ]

    expect(deepestAncestor(candidates, '/orgs/a/ws/eng')?.name).toBe('exact')
  })
})

describe('credential path helpers', () => {
  it('builds and inspects credential paths consistently', () => {
    expect(joinCredentialPath('/', 'github')).toBe('/github')
    expect(joinCredentialPath('/orgs/a', 'github')).toBe('/orgs/a/github')
    expect(credentialParentPath('/github')).toBe('/')
    expect(credentialParentPath('/orgs/a/github')).toBe('/orgs/a')
    expect(credentialName('/orgs/a/github')).toBe('github')
    expect(pathDepth('/')).toBe(0)
    expect(pathDepth('/orgs/a/github')).toBe(3)
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
    await storeCredentialAtPath('cred-a', 'api.example.com', 'secret-a', `/orgs/${ORG_A}`)
    await storeCredentialAtPath('cred-b', 'api.example.com', 'secret-b', `/orgs/${ORG_B}`)

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
        path: `/orgs/${ORG_B}/cred-b`,
      }),
    })
    expect(update.status).toBe(403)

    const remove = await req(`/credentials/cred-b?host=api.example.com&path=${encodeURIComponent(`/orgs/${ORG_B}/cred-b`)}`, {
      method: 'DELETE',
      headers: withToken(tokenA),
    })
    expect(remove.status).toBe(403)
  })

  it('does not let one org proxy or explicitly select another org credential', async () => {
    await storeCredentialAtPath('cred-b', 'api.example.com', 'secret-b', `/orgs/${ORG_B}`)
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

describe('usage flows upward', () => {
  it('lets org tokens use ancestor credentials, including root credentials', async () => {
    await storeCredentialAtPath('org-cred', 'api.example.com', 'org-secret', `/orgs/${ORG_A}`)
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
    expect(await rootRes.json()).toEqual({ auth: 'Bearer global-secret' })
  })
})

describe('admin flows downward', () => {
  it('lets org tokens manage descendant credentials but not ancestors', async () => {
    await storeCredentialAtPath('ws-cred', 'api.example.com', 'ws-secret', `/orgs/${ORG_A}/ws/eng`)
    await storeCredentialAtPath('root-cred', 'api.example.com', 'root-secret', '/')

    const orgToken = mintTestToken(ORG_A)

    const list = await req('/credentials', { headers: withToken(orgToken) })
    expect(list.status).toBe(200)
    const names = ((await list.json()) as { data: { name: string }[] }).data.map(credential => credential.name)
    expect(names).toContain('ws-cred')
    expect(names).toContain('root-cred')

    const deleteDescendant = await req(`/credentials/ws-cred?host=api.example.com&path=${encodeURIComponent(`/orgs/${ORG_A}/ws/eng/ws-cred`)}`, {
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
    const token = mintTestToken(ORG_A)

    const ownPath = await req('/credentials/new-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: `/orgs/${ORG_A}/new-cred`,
      }),
    })
    expect(ownPath.status).toBe(200)

    const deeper = await req('/credentials/deep-cred', {
      method: 'PUT',
      headers: withToken(token, { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        token: 'my-secret',
        host: 'api.example.com',
        path: `/orgs/${ORG_A}/ws/eng/deep-cred`,
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
        path: `/orgs/${ORG_B}/other-cred`,
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
})

describe('profile resolution', () => {
  it('chooses the nearest visible profile for a host', async () => {
    await upsertCredProfile(db, '/github-global', {
      host: ['api.github.com'],
      displayName: 'GitHub Global',
      auth: { kind: 'headers', authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await upsertCredProfile(db, `/orgs/${ORG_A}/github-org`, {
      host: ['api.github.com'],
      displayName: 'GitHub Org Override',
      auth: { kind: 'headers', authSchemes: [{ type: 'http', scheme: 'bearer' }] },
    })
    await storeCredentialAtPath('gh-cred', 'api.github.com', 'gh-secret', `/orgs/${ORG_A}`)

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
    await storeCredentialAtPath('org-gh', 'api.github.com', 'org-token', `/orgs/${ORG_A}`)
    await storeCredentialAtPath('slack-1', 'slack.com', 'xoxb-1', `/orgs/${ORG_A}`)
    await storeCredentialAtPath('slack-2', 'slack.com', 'xoxb-2', `/orgs/${ORG_A}`)

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
    await storeCredentialAtPath('partial-cred', 'api.example.com', 'secret', '/orgs/ab')

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
    await storeCredentialAtPath('cred', 'api.example.com', 'secret', `/orgs/${ORG_A}`)

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
})

describe('credential profile path-based access control', () => {
  it('allows profile creation at the caller path and blocks creation above it', async () => {
    const token = mintTestToken(ORG_A, ['manage_services'])

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

  it('lists only visible profiles across ancestors and descendants', async () => {
    await upsertCredProfile(db, '/global-svc', {
      host: ['api.global.com'],
      displayName: 'Global',
    })
    await upsertCredProfile(db, `/orgs/${ORG_A}/org-svc`, {
      host: ['api.org.com'],
      displayName: 'Org',
    })
    await upsertCredProfile(db, `/orgs/${ORG_B}/other-org-svc`, {
      host: ['api.other.com'],
      displayName: 'Other Org',
    })

    const token = mintTestToken(ORG_A)
    const res = await req('/cred_profiles', { headers: withToken(token) })
    expect(res.status).toBe(200)

    const paths = ((await res.json()) as { data: { path: string }[] }).data.map(profile => profile.path)
    expect(paths).toContain('/global-svc')
    expect(paths).toContain(`/orgs/${ORG_A}/org-svc`)
    expect(paths).not.toContain(`/orgs/${ORG_B}/other-org-svc`)
  })
})
