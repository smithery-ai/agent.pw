import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAgentPw } from 'agent.pw'
import { AgentPwConflictError, AgentPwInputError } from '../packages/server/src/errors'
import { deriveEncryptionKey, encryptCredentials } from '../packages/server/src/lib/credentials-crypto'
import type { Logger } from '../packages/server/src/lib/logger'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

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
  it('validates profile operations and resolves host conflicts', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      encryptionKey: Buffer.alloc(32, 7).toString('base64'),
      logger: silentLogger,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
    })

    expect(await agentPw.profiles.resolve({
      root: '/',
    })).toBeNull()

    await expect(agentPw.profiles.resolve({
      provider: 'linear',
      root: '/../bad-root',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(agentPw.profiles.get('/')).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.profiles.list({ root: '/../bad-root' })).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.profiles.put('/linear', {
      host: [],
    })).rejects.toBeInstanceOf(AgentPwInputError)

    const explicit = await agentPw.profiles.put('/linear', {
      host: ['api.linear.app'],
      displayName: 'Linear Cloud',
      auth: { kind: 'oauth' },
      description: 'Primary profile',
    })
    expect(explicit).toEqual(expect.objectContaining({
      displayName: 'Linear Cloud',
      description: 'Primary profile',
      provider: 'linear',
    }))

    await agentPw.profiles.put('/org_alpha/github', {
      host: ['shared.host'],
    })
    await agentPw.profiles.put('/org_alpha/gitlab', {
      host: ['shared.host'],
    })

    await expect(agentPw.profiles.resolve({
      host: 'shared.host',
      root: '/org_alpha/project',
    })).rejects.toBeInstanceOf(AgentPwConflictError)

    expect(await agentPw.profiles.resolve({
      provider: 'linear',
      host: 'other.host',
      root: '/',
    })).toBeNull()

    expect(await agentPw.profiles.delete('/linear')).toBe(true)
    expect(await agentPw.profiles.delete('/linear')).toBe(false)

    expect((await agentPw.profiles.list()).map(profile => profile.path)).toEqual([
      '/org_alpha/github',
      '/org_alpha/gitlab',
    ])
    expect(await agentPw.profiles.get('/missing')).toBeNull()
    expect(await agentPw.profiles.get('/org_alpha/github')).toEqual(expect.objectContaining({
      path: '/org_alpha/github',
      provider: 'github',
    }))
    expect((await agentPw.profiles.list({ root: '/org_alpha' })).map(profile => profile.path)).toEqual([
      '/org_alpha/github',
      '/org_alpha/gitlab',
    ])
  })

  it('validates credential operations and supports buffer secrets', async () => {
    const db = await createTestDb()
    const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
    const agentPw = await createAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      encryptionKey,
    })

    expect(await agentPw.credentials.resolve({
      host: 'api.linear.app',
      root: '/',
      credentialPath: '/linear',
    })).toBeNull()
    expect(await agentPw.credentials.resolve({
      host: 'api.linear.app',
      root: '/',
    })).toBeNull()

    await expect(agentPw.credentials.resolve({
      host: 'api.linear.app',
      root: '/../bad-root',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(agentPw.credentials.resolve({
      host: 'api.linear.app',
      root: '/org_alpha',
      credentialPath: '/org_beta/linear',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(agentPw.credentials.get('/', 'api.linear.app')).rejects.toBeInstanceOf(AgentPwInputError)
    await expect(agentPw.credentials.list({ root: '/../bad-root' })).rejects.toBeInstanceOf(AgentPwInputError)

    const encryptedBuffer = await encryptCredentials(encryptionKey, {
      headers: { Authorization: 'Bearer buffered-token' },
    })
    const stored = await agentPw.credentials.put('/org_alpha/linear', {
      host: 'api.linear.app',
      secret: encryptedBuffer,
    })
    expect(stored).toEqual(expect.objectContaining({
      auth: { kind: 'opaque' },
      path: '/org_alpha/linear',
      secret: { headers: { Authorization: 'Bearer buffered-token' } },
    }))

    expect(await agentPw.credentials.move('/org_alpha/linear', '/org_alpha/linear-next', 'api.linear.app')).toBe(true)
    expect(await agentPw.credentials.move('/org_alpha/linear', '/org_alpha/linear-next', 'api.linear.app')).toBe(false)
    expect(await agentPw.credentials.delete('/org_alpha/linear-next', 'api.linear.app')).toBe(true)
    expect(await agentPw.credentials.delete('/org_alpha/linear-next', 'api.linear.app')).toBe(false)

    await agentPw.credentials.put('/org_alpha/linear-second', {
      host: 'api.linear.app',
      secret: { headers: { Authorization: 'Bearer second' } },
    })
    expect(await agentPw.credentials.get('/missing', 'api.linear.app')).toBeNull()
    expect((await agentPw.credentials.list()).map(credential => credential.path)).toEqual([
      '/org_alpha/linear-second',
    ])
    expect((await agentPw.credentials.list({ root: '/org_alpha' })).map(credential => credential.path)).toEqual([
      '/org_alpha/linear-second',
    ])
    expect(await agentPw.credentials.resolve({
      host: 'api.linear.app',
      root: '/org_alpha',
      credentialPath: '/org_alpha/linear-second',
    })).toEqual(expect.objectContaining({
      path: '/org_alpha/linear-second',
    }))
  })

  it('surfaces defensive persistence failures for profiles', async () => {
    vi.doMock('../packages/server/src/db/queries.js', async importOriginal => {
      const actual = await importOriginal<typeof import('../packages/server/src/db/queries.js')>()
      return {
        ...actual,
        getCredProfile: vi.fn(async () => null),
      }
    })

    const { createAgentPw: createMockedAgentPw } = await import('../packages/server/src/index.js')
    const db = await createTestDb()
    const agentPw = await createMockedAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      logger: silentLogger,
    })

    await expect(agentPw.profiles.put('/linear', {
      host: ['api.linear.app'],
    })).rejects.toThrow("Failed to persist Credential Profile '/linear'")
  })

  it('surfaces defensive persistence failures for credentials', async () => {
    vi.doMock('../packages/server/src/db/queries.js', async importOriginal => {
      const actual = await importOriginal<typeof import('../packages/server/src/db/queries.js')>()
      return {
        ...actual,
        getCredential: vi.fn(async () => null),
      }
    })

    const { createAgentPw: createMockedAgentPw } = await import('../packages/server/src/index.js')
    const db = await createTestDb()
    const agentPw = await createMockedAgentPw({
      db,
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      logger: silentLogger,
    })

    await expect(agentPw.credentials.put('/linear', {
      host: 'api.linear.app',
      secret: { headers: {} },
    })).rejects.toThrow("Failed to persist Credential '/linear' for 'api.linear.app'")
  })
})
