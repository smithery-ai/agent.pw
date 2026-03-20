import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  readCliConfig,
  readTokenStack,
  writeTokenStack,
  requestJson,
  output,
  outputList,
} = vi.hoisted(() => ({
  readCliConfig: vi.fn(),
  readTokenStack: vi.fn(),
  writeTokenStack: vi.fn(),
  requestJson: vi.fn(),
  output: vi.fn(() => false),
  outputList: vi.fn(() => false),
}))

vi.mock('../packages/cli/src/config', () => ({
  readCliConfig,
  readTokenStack,
  writeTokenStack,
}))

vi.mock('../packages/cli/src/http', () => ({
  requestJson,
}))

vi.mock('../packages/cli/src/output', () => ({
  output,
  outputList,
}))

import { runCli } from '../packages/cli/src/index'
import {
  listTokensCmd,
  popTokenCmd,
  pushProvidedTokenCmd,
  pushTokenCmd,
  revokeTokenCmd,
} from '../packages/cli/src/commands/token'

describe('CLI token stack commands', () => {
  let stack: string[]

  beforeEach(() => {
    vi.clearAllMocks()
    stack = []
    readCliConfig.mockReturnValue({
      url: 'http://localhost:9315',
      token: 'apw_root_token',
    })
    readTokenStack.mockImplementation(() => [...stack])
    writeTokenStack.mockImplementation(next => {
      stack = [...next]
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('pushes a provided token onto the stack for temporary use', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    pushProvidedTokenCmd('apw_test_token')

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_test_token'])
    expect(log).toHaveBeenCalledWith(
      'Pushed provided token (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })

  it('pops back to the previous token after a temporary use', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    readTokenStack.mockReturnValue(['apw_root_token', 'apw_temp_token'])

    popTokenCmd()

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_root_token'])
    expect(log).toHaveBeenCalledWith('Popped token (stack depth: 1)')
  })

  it('routes `token push <token>` through the provided-token stack flow', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw', 'token', 'push', 'apw_cli_token'])

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_cli_token'])
    expect(log).toHaveBeenCalledWith(
      'Pushed provided token (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })

  it('routes `token push` with restrictions through POST /tokens', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    requestJson.mockResolvedValue({
      ok: true,
      id: 'tok_123',
      token: 'apw_child_token',
      name: null,
      rights: [],
      constraints: [],
      createdAt: '2026-03-20T00:00:00.000Z',
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      revokeReason: null,
    })

    await runCli([
      'node',
      'agent.pw',
      'token',
      'push',
      '--host',
      'api.notion.com',
      '--method',
      'get',
      '--path',
      '/v1/pages',
      '--ttl',
      '1h',
    ])

    expect(requestJson).toHaveBeenCalledWith('/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        constraints: [{
          services: 'api.notion.com',
          methods: 'GET',
          paths: '/v1/pages',
          ttl: '1h',
        }],
      }),
    })
    expect(writeTokenStack).toHaveBeenCalledWith(['apw_child_token'])
    expect(log).toHaveBeenCalledWith(
      'Pushed tracked token tok_123 (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })

  it('pushes a tracked restricted token without revoking it on pop', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    requestJson.mockResolvedValue({
      ok: true,
      id: 'tok_push',
      token: 'apw_tracked_child',
      name: null,
      rights: [],
      constraints: [],
      createdAt: '2026-03-20T00:00:00.000Z',
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      revokeReason: null,
    })

    await pushTokenCmd({ services: ['api.github.com'] })
    popTokenCmd()

    expect(requestJson).toHaveBeenCalledTimes(1)
    expect(requestJson).toHaveBeenCalledWith('/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        constraints: [{
          services: 'api.github.com',
        }],
      }),
    })
    expect(log).toHaveBeenNthCalledWith(
      1,
      'Pushed tracked token tok_push (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
    expect(log).toHaveBeenNthCalledWith(2, 'Popped to root token.')
  })

  it('pushes a full-scope tracked token when no restriction flags are provided', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    requestJson.mockResolvedValue({
      ok: true,
      id: 'tok_full_scope',
      token: 'apw_full_scope_child',
      name: null,
      rights: [],
      constraints: [],
      createdAt: '2026-03-20T00:00:00.000Z',
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      revokeReason: null,
    })

    await pushTokenCmd({})

    expect(requestJson).toHaveBeenCalledWith('/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(writeTokenStack).toHaveBeenCalledWith(['apw_full_scope_child'])
    expect(log).toHaveBeenCalledWith(
      'Pushed tracked token tok_full_scope (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })

  it('lists tracked tokens from GET /tokens', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    requestJson.mockResolvedValue({
      data: [{
        id: 'tok_list',
        name: 'Notion sync',
        rights: [{ action: 'credential.read', root: '/org_acme' }],
        constraints: [],
        createdAt: '2026-03-20T00:00:00.000Z',
        expiresAt: null,
        lastUsedAt: '2026-03-20T01:00:00.000Z',
        revokedAt: null,
        revokeReason: null,
      }],
    })

    await listTokensCmd()

    expect(requestJson).toHaveBeenCalledWith('/tokens', { method: 'GET' })
    expect(log).toHaveBeenCalledWith('tok_list Notion sync')
    expect(log).toHaveBeenCalledWith('  rights: credential.read@/org_acme')
  })

  it('revokes tracked tokens by ID through DELETE /tokens/:id', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    requestJson.mockResolvedValue({ ok: true, id: 'tok_revoke' })

    await revokeTokenCmd('tok_revoke', 'rotated')

    expect(requestJson).toHaveBeenCalledWith('/tokens/tok_revoke', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'rotated' }),
    })
    expect(log).toHaveBeenCalledWith('Revoked token tok_revoke.')
  })
})
