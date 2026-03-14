import { beforeEach, describe, expect, it, vi } from 'vitest'

const {
  readLocalConfig,
  describeLocalServer,
  probeLocalServer,
} = vi.hoisted(() => ({
  readLocalConfig: vi.fn(),
  describeLocalServer: vi.fn(),
  probeLocalServer: vi.fn(),
}))

vi.mock('../packages/server/src/local/config', () => ({
  readLocalConfig,
}))

vi.mock('../packages/cli/src/local/server-runtime', () => ({
  describeLocalServer,
  probeLocalServer,
}))

import { statusCmd } from '../packages/cli/src/commands/status'

describe('CLI status', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllEnvs()
  })

  it('reports an unconfigured local instance', async () => {
    readLocalConfig.mockReturnValue(null)
    describeLocalServer.mockReturnValue({ baseUrl: null })

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    await statusCmd()

    expect(logSpy.mock.calls).toEqual([
      ['No agent.pw instance is configured.'],
      ['Run `npx agent.pw init` to create and start a local instance.'],
      ['Or set AGENT_PW_HOST and AGENT_PW_TOKEN for a remote self-hosted deployment.'],
    ])
    expect(probeLocalServer).not.toHaveBeenCalled()
  })

  it('reports a configured local instance as stopped when the daemon is down', async () => {
    readLocalConfig.mockReturnValue({ dataDir: '/tmp/agent.pw/data' })
    describeLocalServer.mockReturnValue({
      baseUrl: 'http://127.0.0.1:9315',
      configFile: '/tmp/agent.pw/config.json',
      logFile: '/tmp/agent.pw/logs/server.log',
      pid: null,
      running: false,
    })

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    await statusCmd()

    expect(logSpy.mock.calls).toEqual([
      ['Config: /tmp/agent.pw/config.json'],
      ['Data:   /tmp/agent.pw/data'],
      ['URL:    http://127.0.0.1:9315'],
      ['Log:    /tmp/agent.pw/logs/server.log'],
      ['State:  stopped'],
    ])
    expect(probeLocalServer).not.toHaveBeenCalled()
  })

  it('reports a reachable remote instance when env configuration is complete', async () => {
    vi.stubEnv('AGENT_PW_HOST', 'http://remote.agentpw.test/')
    vi.stubEnv('AGENT_PW_TOKEN', 'apw_remote')
    probeLocalServer.mockResolvedValue(true)

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    await statusCmd()

    expect(probeLocalServer).toHaveBeenCalledWith('http://remote.agentpw.test')
    expect(logSpy.mock.calls).toEqual([
      ['Mode:   remote'],
      ['URL:    http://remote.agentpw.test'],
      ['Auth:   env'],
      ['State:  reachable'],
    ])
  })

  it('reports incomplete remote env configuration clearly', async () => {
    vi.stubEnv('AGENT_PW_HOST', 'http://remote.agentpw.test')

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    await statusCmd()

    expect(logSpy.mock.calls).toEqual([
      ['Remote agent.pw configuration is incomplete.'],
      ['Missing: AGENT_PW_TOKEN'],
    ])
    expect(probeLocalServer).not.toHaveBeenCalled()
  })
})
