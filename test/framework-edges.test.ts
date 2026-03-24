import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAgentPw } from 'agent.pw'
import { AgentPwAuthorizationError, AgentPwConflictError, AgentPwInputError } from '../packages/server/src/errors'
import { deriveEncryptionKey, encryptCredentials } from '../packages/server/src/lib/credentials-crypto'
import type { Logger } from '../packages/server/src/lib/logger'
import { createTestDb } from './setup'

const silentLogger: Logger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  child() {
    return this
  },
}

afterEach(() => {
  vi.resetModules()
  vi.restoreAllMocks()
})

describe('createAgentPw edge cases', () => {
  it('validates profile and credential operations and surfaces conflicts', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      encryptionKey: Buffer.alloc(32, 7).toString('base64'),
      logger: silentLogger,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    await expect(agentPw.profiles.get('/')).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.profiles.put('/shared/github', {
      resourcePatterns: [],
      auth: { kind: 'headers', fields: [] },
    })).rejects.toThrow('Credential Profile resourcePatterns cannot be empty')

    await agentPw.profiles.put('/shared/github', {
      resourcePatterns: ['https://shared.example.com/*'],
      auth: { kind: 'headers', fields: [{ name: 'Authorization', label: 'Token' }] },
    })
    await agentPw.profiles.put('/shared/gitlab', {
      resourcePatterns: ['https://shared.example.com/*'],
      auth: { kind: 'oauth', authorizationUrl: 'https://auth.example.com/authorize', tokenUrl: 'https://auth.example.com/token', clientId: 'shared-client' },
    })

    await expect(agentPw.profiles.resolve({
      path: '/shared/connections/tool',
      resource: 'https://shared.example.com/api',
    })).rejects.toBeInstanceOf(AgentPwConflictError)

    await expect(agentPw.credentials.get('/')).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.credentials.list({ path: '/../bad' })).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.connect.headers({ path: '/missing' })).rejects.toThrow("No credential exists at '/missing'")

    const encrypted = await encryptCredentials(Buffer.alloc(32, 7).toString('base64'), {
      headers: { Authorization: 'Bearer buffered-token' },
    })
    const stored = await agentPw.credentials.put({
      path: '/shared/connections/buffered',
      resource: 'https://buffered.example.com',
      auth: { kind: 'headers', label: 'Buffered' },
      secret: encrypted,
    })
    expect(stored.secret.headers).toEqual({ Authorization: 'Bearer buffered-token' })

    expect(await agentPw.credentials.move('/shared/connections/buffered', '/shared/connections/buffered_next')).toBe(true)
    expect(await agentPw.credentials.move('/shared/connections/buffered', '/shared/connections/buffered_next')).toBe(false)
    expect(await agentPw.credentials.delete('/shared/connections/buffered_next')).toBe(true)
    expect(await agentPw.credentials.delete('/shared/connections/buffered_next')).toBe(false)
  })

  it('validates connect helpers and authorization denials', async () => {
    const db = await createTestDb()
    const encryptionKey = await deriveEncryptionKey('ed25519-private/20cbf8e88a4d258a2af3b2ab1132ae6f753e46893eaea2427f732feefba7a8ad')
    const agentPw = await createAgentPw({
      db,
      encryptionKey,
    })

    await agentPw.profiles.put('/resend', {
      resourcePatterns: ['https://api.resend.com*'],
      auth: {
        kind: 'headers',
        fields: [{ name: 'Authorization', label: 'API key', prefix: 'Bearer ' }],
      },
    })

    const prepared = await agentPw.connect.prepare({
      path: '/org/connections/resend',
      resource: 'https://api.resend.com',
    })
    expect(prepared.kind).toBe('options')
    if (prepared.kind !== 'options') {
      throw new Error('Expected options')
    }

    await expect(agentPw.connect.saveHeaders({
      path: '/org/connections/resend',
      option: prepared.options[0],
      values: {},
    })).rejects.toThrow("Missing header value for 'Authorization'")

    await expect(agentPw.connect.saveHeaders({
      path: '/org/connections/raw',
      option: {
        kind: 'headers',
        source: 'profile',
        label: 'Raw token',
        profilePath: '/resend',
        resource: 'https://api.resend.com/',
        fields: [{ name: 'Authorization', label: 'Token' }],
      },
      values: { Authorization: 'plain-token' },
    })).resolves.toEqual(expect.objectContaining({
      secret: {
        headers: {
          Authorization: 'plain-token',
        },
      },
    }))

    await expect(agentPw.connect.saveHeaders({
      path: '/org/connections/resend',
      option: {
        kind: 'oauth',
        source: 'profile',
        label: 'Wrong',
        profilePath: '/resend',
        resource: 'https://api.resend.com/',
      },
      values: {},
    })).rejects.toThrow('connect.saveHeaders requires a headers option')

    await expect(agentPw.authenticated({
      rights: [{ action: 'credential.read', root: '/elsewhere' }],
      userId: 'user_123',
      orgId: null,
      homePath: null,
      scopes: [],
    }, api => api.credentials.get('/org/connections/resend'))).rejects.toBeInstanceOf(AgentPwAuthorizationError)
  })

  it('falls back to the existing oauth credential when refresh lookup races to null', async () => {
    vi.doMock('../packages/server/src/db/queries.js', async importOriginal => {
      const actual = await importOriginal<typeof import('../packages/server/src/db/queries.js')>()
      const helpers = actual.createQueryHelpers()
      let reads = 0
      return {
        ...actual,
        createQueryHelpers: vi.fn(() => ({
          ...helpers,
          getCredential: vi.fn(async (_db, path) => {
            if (path !== '/org/connections/docs') {
              return helpers.getCredential(_db, path)
            }
            reads += 1
            if (reads <= 2) {
              return helpers.getCredential(_db, path)
            }
            return null
          }),
        })),
      }
    })

    const { createAgentPw: createMockedAgentPw } = await import('../packages/server/src/index.js')
    const db = await createTestDb()
    const agentPw = await createMockedAgentPw({
      db,
      encryptionKey: Buffer.alloc(32, 7).toString('base64'),
    })

    await agentPw.credentials.put({
      path: '/org/connections/docs',
      resource: 'https://docs.example.com/mcp',
      auth: { kind: 'oauth', label: 'Docs' },
      secret: {
        headers: { Authorization: 'Bearer docs-token' },
        oauth: {
          accessToken: 'docs-token',
        },
      },
    })

    await expect(agentPw.connect.prepare({
      path: '/org/connections/docs',
      resource: 'https://docs.example.com/mcp',
    })).resolves.toEqual(expect.objectContaining({
      kind: 'ready',
      credential: expect.objectContaining({
        path: '/org/connections/docs',
        auth: expect.objectContaining({
          kind: 'oauth',
          label: 'Docs',
        }),
      }),
      headers: {
        Authorization: 'Bearer docs-token',
      },
    }))
  })

  it('surfaces defensive persistence failures for profiles and credentials', async () => {
    vi.doMock('../packages/server/src/db/queries.js', async importOriginal => {
      const actual = await importOriginal<typeof import('../packages/server/src/db/queries.js')>()
      const helpers = actual.createQueryHelpers()
      return {
        ...actual,
        createQueryHelpers: vi.fn(() => ({
          ...helpers,
          getCredProfile: vi.fn(async () => null),
          getCredential: vi.fn(async () => null),
        })),
      }
    })

    const { createAgentPw: createMockedAgentPw } = await import('../packages/server/src/index.js')
    const db = await createTestDb()
    const agentPw = await createMockedAgentPw({
      db,
      encryptionKey: Buffer.alloc(32, 7).toString('base64'),
    })

    await expect(agentPw.profiles.put('/linear', {
      resourcePatterns: ['https://api.linear.app/*'],
      auth: { kind: 'headers', fields: [{ name: 'Authorization', label: 'Token' }] },
    })).rejects.toThrow("Failed to persist Credential Profile '/linear'")

    await expect(agentPw.credentials.put({
      path: '/org/connections/linear',
      resource: 'https://api.linear.app',
      auth: { kind: 'headers' },
      secret: { headers: { Authorization: 'Bearer token' } },
    })).rejects.toThrow("Failed to persist Credential '/org/connections/linear'")
  })
})
