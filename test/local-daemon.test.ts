import { EventEmitter } from 'node:events'
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { writeLocalConfig, writeLocalPid } from '../packages/server/src/local/config'

const tempDirs: string[] = []

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.resetModules()
  tempDirs.splice(0).forEach(dir => {
    rmSync(dir, { recursive: true, force: true })
  })
})

function createTempHome() {
  const homeDir = mkdtempSync(join(tmpdir(), 'agentpw-daemon-test-'))
  tempDirs.push(homeDir)
  return homeDir
}

describe('local daemon helper', () => {
  it('fails clearly when no local config exists yet', async () => {
    const homeDir = createTempHome()
    const pathsModule = await import('../packages/server/src/local/config')
    const paths = pathsModule.localAgentPwPaths(homeDir)

    const daemon = await import('../packages/server/src/local/daemon')

    await expect(daemon.ensureLocalServerDaemon({
      command: 'bun',
      args: ['cli.ts', 'start'],
    }, paths)).rejects.toThrow('agent.pw is not initialized. Run `npx agent.pw init` first.')
  })

  it('returns the existing local server when the configured base URL is already reachable', async () => {
    const homeDir = createTempHome()
    const pathsModule = await import('../packages/server/src/local/config')
    const paths = pathsModule.localAgentPwPaths(homeDir)

    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })))
    const spawn = vi.fn()
    vi.doMock('node:child_process', () => ({
      spawn,
    }))
    const daemon = await import('../packages/server/src/local/daemon')

    await expect(daemon.ensureLocalServerDaemon({
      command: 'bun',
      args: ['cli.ts', 'start'],
    }, paths)).resolves.toEqual({
      started: false,
      baseUrl: 'http://127.0.0.1:9315',
      pid: null,
      logFile: paths.logFile,
    })

    expect(spawn).not.toHaveBeenCalled()
  })

  it('replaces a tracked but unhealthy daemon before starting a new one', async () => {
    const homeDir = createTempHome()
    const pathsModule = await import('../packages/server/src/local/config')
    const paths = pathsModule.localAgentPwPaths(homeDir)

    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)
    writeLocalPid(5151, paths)
    mkdirSync(paths.logsDir, { recursive: true })

    vi.stubGlobal('fetch', vi.fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(new Response('ok', { status: 200 })))
    const killSpy = vi.spyOn(process, 'kill').mockImplementation(((_pid: number, signal?: number | NodeJS.Signals) => {
      if (signal === 0 || signal === 'SIGTERM') {
        return true
      }
      return true
    }) as typeof process.kill)

    const child = new EventEmitter() as EventEmitter & {
      pid: number
      unref: () => void
      once: typeof EventEmitter.prototype.once
    }
    child.pid = 6161
    child.unref = vi.fn()

    const spawn = vi.fn().mockImplementation(() => {
      queueMicrotask(() => {
        writeLocalPid(6161, paths)
      })
      return child
    })
    vi.doMock('node:child_process', () => ({
      spawn,
    }))

    const daemon = await import('../packages/server/src/local/daemon')

    await expect(daemon.ensureLocalServerDaemon({
      command: 'bun',
      args: ['cli.ts', 'start'],
    }, paths)).resolves.toEqual({
      started: true,
      baseUrl: 'http://127.0.0.1:9315',
      pid: 6161,
      logFile: paths.logFile,
    })

    expect(killSpy).toHaveBeenCalledWith(5151, 'SIGTERM')
  })

  it('starts and waits for a managed local daemon when the server is down', async () => {
    const homeDir = createTempHome()
    const pathsModule = await import('../packages/server/src/local/config')
    const paths = pathsModule.localAgentPwPaths(homeDir)

    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)
    mkdirSync(paths.logsDir, { recursive: true })

    vi.stubGlobal('fetch', vi.fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(new Response('ok', { status: 200 })))
    vi.spyOn(process, 'kill').mockImplementation(((_pid: number, signal?: number | NodeJS.Signals) => {
      if (signal === 0) {
        return true
      }
      return true
    }) as typeof process.kill)

    const child = new EventEmitter() as EventEmitter & {
      pid: number
      unref: () => void
      once: typeof EventEmitter.prototype.once
    }
    child.pid = 4242
    child.unref = vi.fn()

    const spawn = vi.fn().mockImplementation(() => {
      queueMicrotask(() => {
        writeLocalPid(4242, paths)
      })
      return child
    })
    vi.doMock('node:child_process', () => ({
      spawn,
    }))

    const daemon = await import('../packages/server/src/local/daemon')

    await expect(daemon.ensureLocalServerDaemon({
      command: 'bun',
      args: ['cli.ts', 'start'],
    }, paths)).resolves.toEqual({
      started: true,
      baseUrl: 'http://127.0.0.1:9315',
      pid: 4242,
      logFile: paths.logFile,
    })

    expect(spawn).toHaveBeenCalled()
    expect(child.unref).toHaveBeenCalled()
  })

  it('fails when the spawned daemon exits before becoming healthy', async () => {
    const homeDir = createTempHome()
    const pathsModule = await import('../packages/server/src/local/config')
    const paths = pathsModule.localAgentPwPaths(homeDir)

    writeLocalConfig({
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }, paths)
    mkdirSync(paths.logsDir, { recursive: true })

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))

    const child = new EventEmitter() as EventEmitter & {
      pid: number
      unref: () => void
      once: typeof EventEmitter.prototype.once
    }
    child.pid = 4242
    child.unref = vi.fn()

    const spawn = vi.fn().mockImplementation(() => {
      queueMicrotask(() => {
        child.emit('exit', 1)
      })
      return child
    })
    vi.doMock('node:child_process', () => ({
      spawn,
    }))

    const daemon = await import('../packages/server/src/local/daemon')

    await expect(daemon.ensureLocalServerDaemon({
      command: 'bun',
      args: ['cli.ts', 'start'],
    }, paths)).rejects.toThrow(`Local agent.pw daemon exited before startup. Check ${paths.logFile}.`)
  })
})
