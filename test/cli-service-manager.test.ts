import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { localAgentPwPaths, writeLocalConfig, writeLocalPid } from '../packages/server/src/local/config'

const {
  execFileSync,
  probeLocalServer,
} = vi.hoisted(() => ({
  execFileSync: vi.fn(),
  probeLocalServer: vi.fn(),
}))

vi.mock('node:child_process', () => ({
  execFileSync,
}))

vi.mock('../packages/cli/src/local/server-runtime', () => ({
  probeLocalServer,
}))

const tempDirs: string[] = []

function createTempDir(prefix: string) {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`))
  tempDirs.push(dir)
  return dir
}

describe('CLI service manager', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.unstubAllEnvs()
    execFileSync.mockImplementation((_command, _args, options) => {
      if (options && typeof options === 'object' && 'encoding' in options) {
        return ''
      }
      return undefined
    })
  })

  afterEach(() => {
    tempDirs.splice(0).forEach(dir => {
      rmSync(dir, { recursive: true, force: true })
    })
  })

  it('installs a managed local service for the current platform', async () => {
    const homeDir = createTempDir('agentpw-home')
    const serviceDir = createTempDir('agentpw-service')
    const paths = localAgentPwPaths(homeDir)
    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)
    writeLocalPid(process.pid, paths)

    vi.stubEnv('AGENTPW_SERVICE_DIR', serviceDir)
    probeLocalServer.mockResolvedValue(true)

    const { ensureLocalService, describeLocalService } = await import('../packages/cli/src/local/service-manager')
    const runner = {
      command: process.execPath,
      args: ['/tmp/local-daemon.js'],
      displayPath: '/tmp/local-daemon.js',
      source: 'bundle' as const,
    }

    const service = await ensureLocalService(runner, paths)
    const described = describeLocalService()

    expect(service.changed).toBe(true)
    expect(service.baseUrl).toBe('http://127.0.0.1:9315')
    expect(service.servicePath).toBe(described.filePath)
    expect(described.installed).toBe(true)
    expect(described.running).toBe(false)
    expect(described.kind).toBe(process.platform === 'darwin' ? 'launchd' : 'systemd')
    expect(described.pid).toBeNull()
    expect(existsSync(service.servicePath)).toBe(true)

    const contents = readFileSync(service.servicePath, 'utf8')
    expect(contents).toContain('/tmp/local-daemon.js')
    expect(contents).toContain('serve')

    if (process.platform === 'darwin') {
      expect(execFileSync).toHaveBeenCalledWith('launchctl', expect.any(Array), { stdio: 'ignore' })
    } else {
      expect(execFileSync).toHaveBeenCalledWith('systemctl', expect.any(Array), { stdio: 'ignore' })
    }
  })

  it('stops the managed local service without deleting local data', async () => {
    const homeDir = createTempDir('agentpw-home')
    const serviceDir = createTempDir('agentpw-service')
    const paths = localAgentPwPaths(homeDir)
    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)

    vi.stubEnv('AGENTPW_SERVICE_DIR', serviceDir)
    probeLocalServer.mockResolvedValue(true)

    const { ensureLocalService, stopLocalService, describeLocalService } = await import('../packages/cli/src/local/service-manager')
    const runner = {
      command: process.execPath,
      args: ['/tmp/local-daemon.js'],
      displayPath: '/tmp/local-daemon.js',
      source: 'bundle' as const,
    }

    writeLocalPid(process.pid, paths)
    const service = await ensureLocalService(runner, paths)
    expect(existsSync(service.servicePath)).toBe(true)

    const removed = stopLocalService(paths)
    expect(removed).toBe(true)
    expect(existsSync(service.servicePath)).toBe(false)
    expect(existsSync(paths.configFile)).toBe(true)
    expect(describeLocalService().installed).toBe(false)
  })
})
