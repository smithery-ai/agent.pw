import { beforeEach, describe, expect, it, vi } from 'vitest'

const {
  localAgentPwPaths,
  readLocalConfig,
  ensureLocalCliConfig,
  buildVaultLaunchUrl,
  describeLocalServer,
  readLocalServerLogs,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
  detectUnmanagedLocalServer,
  ensureLocalService,
  stopLocalService,
  stopUnmanagedLocalServer,
  confirmTakeoverRunningProcess,
  openBrowser,
  buildCliHelpFooter,
  printAgentPwSkillInstallHint,
  printBinarySource,
  printOnboardingHeader,
  printOnboardingStep,
  printOnboardingSuccess,
} = vi.hoisted(() => ({
  localAgentPwPaths: vi.fn(),
  readLocalConfig: vi.fn(),
  ensureLocalCliConfig: vi.fn(),
  buildVaultLaunchUrl: vi.fn(),
  describeLocalServer: vi.fn(),
  readLocalServerLogs: vi.fn(),
  resolveLocalDaemonRunner: vi.fn(),
  runLocalServerDaemonCommand: vi.fn(),
  detectUnmanagedLocalServer: vi.fn(),
  ensureLocalService: vi.fn(),
  stopLocalService: vi.fn(),
  stopUnmanagedLocalServer: vi.fn(),
  confirmTakeoverRunningProcess: vi.fn(),
  openBrowser: vi.fn(),
  buildCliHelpFooter: vi.fn(),
  printAgentPwSkillInstallHint: vi.fn(),
  printBinarySource: vi.fn(),
  printOnboardingHeader: vi.fn(),
  printOnboardingStep: vi.fn(),
  printOnboardingSuccess: vi.fn(),
}))

vi.mock('../packages/server/src/local/config', () => ({
  localAgentPwPaths,
  readLocalConfig,
}))

vi.mock('../packages/cli/src/config', () => ({
  ensureLocalCliConfig,
}))

vi.mock('../packages/cli/src/local/server-runtime', () => ({
  buildVaultLaunchUrl,
  describeLocalServer,
  readLocalServerLogs,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
}))

vi.mock('../packages/cli/src/local/service-manager', () => ({
  detectUnmanagedLocalServer,
  ensureLocalService,
  stopLocalService,
  stopUnmanagedLocalServer,
}))

vi.mock('../packages/cli/src/local/onboarding', () => ({
  confirmTakeoverRunningProcess,
  openBrowser,
  buildCliHelpFooter,
  printAgentPwSkillInstallHint,
  printBinarySource,
  printOnboardingHeader,
  printOnboardingStep,
  printOnboardingSuccess,
}))

import { runCli } from '../packages/cli/src/index'
import { start } from '../packages/cli/src/commands/start'

describe('CLI start', () => {
  beforeEach(() => {
    vi.clearAllMocks()

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
    ensureLocalCliConfig.mockReturnValue({
      url: 'http://127.0.0.1:9315',
      token: 'apw_root',
    })
    resolveLocalDaemonRunner.mockReturnValue({
      command: process.execPath,
      args: ['/tmp/local-daemon.js'],
      displayPath: '/tmp/local-daemon.js',
      source: 'bundle',
    })
    runLocalServerDaemonCommand.mockResolvedValue('bootstrap-token')
    detectUnmanagedLocalServer.mockResolvedValue(null)
    ensureLocalService.mockResolvedValue({
      baseUrl: 'http://127.0.0.1:9315',
      changed: true,
      kind: 'launchd',
      logFile: '/tmp/agent.pw/logs/server.log',
      servicePath: '/tmp/LaunchAgents/ai.agentpw.daemon.plist',
    })
    buildVaultLaunchUrl.mockReturnValue(
      'https://agent.pw/vault?url=http://127.0.0.1:9315#agentpw_token=bootstrap-token',
    )
    buildCliHelpFooter.mockReturnValue('')
    openBrowser.mockReturnValue(false)
  })

  it('aborts when an unmanaged local process is found and the user declines takeover', async () => {
    detectUnmanagedLocalServer.mockResolvedValue({
      baseUrl: 'http://127.0.0.1:9315',
      pids: [1234],
    })
    confirmTakeoverRunningProcess.mockResolvedValue(false)

    await expect(start({ noBrowser: true })).rejects.toThrow(
      'A process is already responding at http://127.0.0.1:9315. Stop it manually or rerun interactively to let agent.pw take over.',
    )

    expect(ensureLocalCliConfig).not.toHaveBeenCalled()
    expect(stopUnmanagedLocalServer).not.toHaveBeenCalled()
    expect(ensureLocalService).not.toHaveBeenCalled()
  })

  it('kills the unmanaged process before installing the managed service', async () => {
    detectUnmanagedLocalServer.mockResolvedValue({
      baseUrl: 'http://127.0.0.1:9315',
      pids: [1234],
    })
    confirmTakeoverRunningProcess.mockResolvedValue(true)

    await start({ noBrowser: true })

    expect(stopUnmanagedLocalServer).toHaveBeenCalledWith({
      baseUrl: 'http://127.0.0.1:9315',
      pids: [1234],
    })
    expect(ensureLocalCliConfig).toHaveBeenCalledWith({
      biscuitPrivateKey: 'test-private-key',
      port: 9315,
      dataDir: '/tmp/agent.pw/data',
    }, expect.anything())
    expect(ensureLocalService).toHaveBeenCalled()
    expect(printAgentPwSkillInstallHint).toHaveBeenCalled()
    expect(printOnboardingStep).toHaveBeenCalledWith(
      '[2/3] Starting agent.pw in the background...',
    )
    expect(printOnboardingStep).toHaveBeenCalledWith(
      '[3/3] Preparing your browser setup link...',
    )
  })

  it('drives the public start command through the hosted bootstrap URL flow', async () => {
    await runCli(['node', 'agent.pw', 'start', '--no-browser'])

    expect(runLocalServerDaemonCommand).toHaveBeenCalledWith(
      expect.anything(),
      ['setup'],
      expect.anything(),
    )
    expect(runLocalServerDaemonCommand).toHaveBeenCalledWith(
      expect.anything(),
      ['bootstrap-token', '--ttl', '10m'],
      expect.anything(),
    )
    expect(buildVaultLaunchUrl).toHaveBeenCalledWith(
      'http://127.0.0.1:9315',
      'bootstrap-token',
    )
    expect(openBrowser).not.toHaveBeenCalled()
    expect(printOnboardingSuccess).toHaveBeenCalledWith(
      'https://agent.pw/vault?url=http://127.0.0.1:9315#agentpw_token=bootstrap-token',
      false,
    )
  })
})
