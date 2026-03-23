import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  readCliConfig,
  readTokenStack,
  readLocalConfig,
  spawn,
} = vi.hoisted(() => ({
  readCliConfig: vi.fn(),
  readTokenStack: vi.fn(),
  readLocalConfig: vi.fn(),
  spawn: vi.fn(),
}))

vi.mock('../packages/cli/src/config', () => ({
  readCliConfig,
  readTokenStack,
}))

vi.mock('../packages/server/src/local/config', async () => {
  const actual = await vi.importActual<
    typeof import('../packages/server/src/local/config')
  >('../packages/server/src/local/config')
  return {
    ...actual,
    readLocalConfig,
  }
})

vi.mock('node:child_process', () => ({
  spawn,
}))

import {
  buildProxyEnvironment,
  normalizeExecArgs,
  resolveLocalProxySettings,
} from '../packages/cli/src/commands/proxy'
import { runCli } from '../packages/cli/src/index'

describe('CLI proxy helpers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    readLocalConfig.mockReturnValue({
      biscuitPrivateKey: 'test-private-key',
      port: 9315,
      dataDir: '/tmp/agent.pw',
    })
    readCliConfig.mockReturnValue({
      url: 'http://127.0.0.1:9315',
      token: 'apw_root_token',
    })
    readTokenStack.mockReturnValue([])
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('builds forward-proxy env vars from the current scoped token', () => {
    const env = buildProxyEnvironment(
      'http://127.0.0.1:9315',
      'apw_scoped/token',
      { NO_PROXY: 'internal.local,localhost' },
    )

    expect(env.HTTP_PROXY).toBe(
      'http://agentpw:apw_scoped%2Ftoken@127.0.0.1:9315',
    )
    expect(env.HTTPS_PROXY).toBe(env.HTTP_PROXY)
    expect(env.ALL_PROXY).toBe(env.HTTP_PROXY)
    expect(env.NO_PROXY).toBe('internal.local,localhost,127.0.0.1,::1')
    expect(env.no_proxy).toBe('internal.local,localhost,127.0.0.1,::1')
  })

  it('prefers the pushed token stack when building local proxy settings', () => {
    readTokenStack.mockReturnValue(['apw_root_token', 'apw_scoped_token'])

    expect(resolveLocalProxySettings()).toEqual({
      baseUrl: 'http://127.0.0.1:9315',
      token: 'apw_scoped_token',
    })
  })

  it('prints shell exports for local proxy env', async () => {
    readTokenStack.mockReturnValue(['apw_child_token'])
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw', 'proxy', 'env'])

    expect(log).toHaveBeenCalledWith(
      "export HTTP_PROXY='http://agentpw:apw_child_token@127.0.0.1:9315'",
    )
    expect(log).toHaveBeenCalledWith(
      "export HTTPS_PROXY='http://agentpw:apw_child_token@127.0.0.1:9315'",
    )
    expect(log).toHaveBeenCalledWith(
      "export NO_PROXY='127.0.0.1,localhost,::1'",
    )
  })

  it('runs a child command with proxy env configured', async () => {
    spawn.mockImplementation((_file: string, _args: string[], _opts: object) => {
      const child = new EventEmitter()
      queueMicrotask(() => child.emit('close', 0))
      return child
    })

    await runCli(['node', 'agent.pw', 'exec', '--', 'demo-cli', '--verbose'])

    expect(spawn).toHaveBeenCalledWith(
      'demo-cli',
      ['--verbose'],
      expect.objectContaining({
        stdio: 'inherit',
        env: expect.objectContaining({
          HTTP_PROXY: 'http://agentpw:apw_root_token@127.0.0.1:9315',
          HTTPS_PROXY: 'http://agentpw:apw_root_token@127.0.0.1:9315',
          NO_PROXY: '127.0.0.1,localhost,::1',
        }),
      }),
    )
  })

  it('normalizes the leading separator for exec passthrough args', () => {
    expect(normalizeExecArgs(['--', 'curl', '-I'])).toEqual(['curl', '-I'])
    expect(normalizeExecArgs(['curl', '-I'])).toEqual(['curl', '-I'])
  })
})
