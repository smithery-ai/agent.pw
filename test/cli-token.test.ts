import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  localAgentPwPaths,
  readLocalConfig,
  buildLocalBaseUrl,
  buildVaultLaunchUrl,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
} = vi.hoisted(() => ({
  localAgentPwPaths: vi.fn(),
  readLocalConfig: vi.fn(),
  buildLocalBaseUrl: vi.fn(),
  buildVaultLaunchUrl: vi.fn(),
  resolveLocalDaemonRunner: vi.fn(),
  runLocalServerDaemonCommand: vi.fn(),
}))

vi.mock('../packages/server/src/local/config', () => ({
  localAgentPwPaths,
  readLocalConfig,
  buildLocalBaseUrl,
}))

vi.mock('../packages/cli/src/local/server-runtime', () => ({
  buildVaultLaunchUrl,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
}))

import { runCli } from '../packages/cli/src/index'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CLI bootstrap token helpers', () => {
  beforeEach(() => {
    localAgentPwPaths.mockReturnValue({
      homeDir: '/tmp/agent.pw',
      configFile: '/tmp/agent.pw/server.json',
      cliConfigFile: '/tmp/agent.pw/cli.json',
      dataDir: '/tmp/agent.pw/data',
      logFile: '/tmp/agent.pw/logs/server.log',
    })
    readLocalConfig.mockReturnValue({
      biscuitPrivateKey: 'test-private-key',
      port: 9315,
      dataDir: '/tmp/agent.pw/data',
    })
    buildLocalBaseUrl.mockReturnValue('http://127.0.0.1:9315')
    buildVaultLaunchUrl.mockReturnValue(
      'https://agent.pw/vault?url=http://127.0.0.1:9315#agentpw_token=apw_bootstrap_123',
    )
    resolveLocalDaemonRunner.mockReturnValue({
      command: process.execPath,
      args: ['/tmp/local-daemon.js'],
      displayPath: '/tmp/local-daemon.js',
      source: 'bundle',
    })
    runLocalServerDaemonCommand.mockResolvedValue('apw_bootstrap_123')
  })

  it('prints a bootstrap token via the public CLI command', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw', 'token', 'bootstrap', '--ttl', '5m'])

    expect(runLocalServerDaemonCommand).toHaveBeenCalledWith(
      expect.anything(),
      ['bootstrap-token', '--ttl', '5m'],
      expect.anything(),
    )
    expect(log).toHaveBeenCalledWith('apw_bootstrap_123')
  })

  it('prints a hosted vault bootstrap URL via the public CLI command', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw', 'token', 'connect-url', '--ttl', '15m'])

    expect(buildVaultLaunchUrl).toHaveBeenCalledWith(
      'http://127.0.0.1:9315',
      'apw_bootstrap_123',
      undefined,
    )
    expect(log).toHaveBeenCalledWith(
      'https://agent.pw/vault?url=http://127.0.0.1:9315#agentpw_token=apw_bootstrap_123',
    )
  })
})
