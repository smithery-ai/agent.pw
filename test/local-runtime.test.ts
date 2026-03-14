import { EventEmitter } from 'node:events'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { authorizeRequest, getPublicKeyHex } from '../packages/server/src/biscuit'
import {
  buildLocalBaseUrl,
  clearStaleLocalPid,
  ensureLocalAgentPwDirs,
  isProcessAlive,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
  removeLocalPid,
  resolveAgentPwHome,
  resolveLocalPort,
  writeExecutableFile,
  writeLocalConfig,
  writeLocalPid,
} from '../packages/server/src/local/config'
import {
  ensureLocalConfig,
  initializeLocalConfig,
  localConfigSummary,
  mintBootstrapToken,
} from '../packages/server/src/local/setup'

const tempDirs: string[] = []

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  tempDirs.splice(0).forEach(dir => {
    rmSync(dir, { recursive: true, force: true })
  })
})

function createTempHome() {
  const homeDir = mkdtempSync(join(tmpdir(), 'agentpw-local-test-'))
  tempDirs.push(homeDir)
  return homeDir
}

describe('local config helpers', () => {
  it('manages config, pid files, and executable runtime assets', () => {
    const homeDir = createTempHome()
    vi.stubEnv('AGENTPW_HOME', homeDir)

    const paths = localAgentPwPaths()
    expect(resolveAgentPwHome()).toBe(homeDir)
    expect(buildLocalBaseUrl(9315)).toBe('http://127.0.0.1:9315')

    ensureLocalAgentPwDirs(paths)
    expect(existsSync(paths.logsDir)).toBe(true)
    expect(existsSync(paths.serverRuntimeDir)).toBe(true)
    expect(readLocalConfig(paths)).toBeNull()
    expect(readLocalPid(paths)).toBeNull()
    expect(clearStaleLocalPid(paths)).toBe(false)

    writeFileSync(paths.configFile, '{broken')
    expect(readLocalConfig(paths)).toBeNull()

    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }

    writeLocalConfig(config, paths)
    expect(readLocalConfig(paths)).toEqual(config)

    writeFileSync(paths.pidFile, 'not-a-pid')
    expect(readLocalPid(paths)).toBeNull()

    writeLocalPid(4321, paths)
    expect(readLocalPid(paths)).toBe(4321)

    const killSpy = vi.spyOn(process, 'kill')
    killSpy.mockImplementation(((_pid: number, signal?: number | NodeJS.Signals) => {
      if (signal === 0) return true
      return true
    }) as typeof process.kill)

    expect(isProcessAlive(4321)).toBe(true)
    expect(clearStaleLocalPid(paths)).toBe(false)

    killSpy.mockImplementation((() => {
      throw new Error('missing')
    }) as typeof process.kill)

    expect(isProcessAlive(4321)).toBe(false)
    expect(clearStaleLocalPid(paths)).toBe(true)
    expect(readLocalPid(paths)).toBeNull()

    removeLocalPid(paths)

    const executablePath = join(paths.runtimeDir, 'bin', 'agentpw')
    writeExecutableFile(executablePath, '#!/bin/sh\necho ok\n')
    expect(readFileSync(executablePath, 'utf8')).toContain('echo ok')
    expect(statSync(executablePath).mode & 0o777).toBe(0o755)
  })

  it('falls back to ~/.agent.pw when no home override is set', () => {
    expect(resolveAgentPwHome()).toContain('.agent.pw')
  })

  it('supports overriding the default local port via env', () => {
    expect(resolveLocalPort()).toBe(9315)

    vi.stubEnv('AGENTPW_LOCAL_PORT', '19415')
    expect(resolveLocalPort()).toBe(19415)

    vi.stubEnv('AGENTPW_LOCAL_PORT', '70000')
    expect(() => resolveLocalPort()).toThrow('Invalid AGENTPW_LOCAL_PORT: 70000')
  })
})

describe('local setup helpers', () => {
  it('initializes local config idempotently and mints restricted bootstrap tokens', async () => {
    const homeDir = createTempHome()
    const paths = localAgentPwPaths(homeDir)

    const config = await initializeLocalConfig(paths, 9410)
    expect(config.masterToken.startsWith('apw_')).toBe(true)
    expect(config.port).toBe(9410)
    expect(readLocalConfig(paths)).toEqual(config)

    const again = await ensureLocalConfig(paths)
    expect(again).toEqual(config)

    expect(localConfigSummary(config, paths)).toEqual({
      configDir: homeDir,
      configFile: paths.configFile,
      dataDir: paths.dataDir,
      port: 9410,
    })

    const bootstrapToken = mintBootstrapToken(config, '5m')
    const publicKeyHex = getPublicKeyHex(config.biscuitPrivateKey)

    expect(
      authorizeRequest(
        bootstrapToken,
        publicKeyHex,
        '_management',
        'GET',
        '/credentials',
        { action: '_management' },
      ).authorized,
    ).toBe(true)

    expect(
      authorizeRequest(
        bootstrapToken,
        publicKeyHex,
        '_management',
        'POST',
        '/tokens/restrict',
        { action: '_management' },
      ).authorized,
    ).toBe(true)

    expect(
      authorizeRequest(
        bootstrapToken,
        publicKeyHex,
        '_management',
        'GET',
        '/admin',
        { action: '_management' },
      ).authorized,
    ).toBe(false)

    expect(
      authorizeRequest(
        bootstrapToken,
        publicKeyHex,
        'api.github.com',
        'GET',
        '/user',
      ).authorized,
    ).toBe(false)
  })
})

describe('local runtime helpers', () => {
  it('tracks status, probes health, waits for readiness, and stops the local server', async () => {
    const homeDir = createTempHome()
    const paths = localAgentPwPaths(homeDir)

    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }

    writeLocalConfig(config, paths)

    const runtime = await import('../packages/server/src/local/runtime')

    expect(runtime.getLocalServerStatus(paths)).toEqual({
      configured: true,
      running: false,
      pid: null,
      baseUrl: 'http://127.0.0.1:9315',
    })

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('ok', { status: 200 })))
    expect(await runtime.probeLocalServer('http://127.0.0.1:9315')).toBe(true)

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    expect(await runtime.probeLocalServer('http://127.0.0.1:9315')).toBe(false)

    const waitFetch = vi
      .fn()
      .mockRejectedValueOnce(new Error('cold start'))
      .mockResolvedValueOnce(new Response('ok', { status: 200 }))
    vi.stubGlobal('fetch', waitFetch)
    await runtime.waitForLocalServer('http://127.0.0.1:9315', 200, 1)

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('still starting')))
    await expect(
      runtime.waitForLocalServer('http://127.0.0.1:9315', 5, 1),
    ).rejects.toThrow('Timed out waiting for agent.pw')

    const killSpy = vi.spyOn(process, 'kill')
    killSpy.mockImplementation(((_pid: number, signal?: number | NodeJS.Signals) => {
      if (signal === 0) return true
      return true
    }) as typeof process.kill)

    writeLocalPid(9876, paths)
    expect(runtime.getLocalServerStatus(paths)).toEqual({
      configured: true,
      running: true,
      pid: 9876,
      baseUrl: 'http://127.0.0.1:9315',
    })

    expect(runtime.stopLocalServer(paths)).toBe(true)
    expect(killSpy).toHaveBeenCalledWith(9876, 'SIGTERM')
    expect(readLocalPid(paths)).toBeNull()
    expect(runtime.stopLocalServer(paths)).toBe(false)
  })

  it('writes the pid after the local app starts', async () => {
    const homeDir = createTempHome()
    vi.resetModules()

    const serveLocalServer = vi.fn().mockResolvedValue({ ok: true })
    vi.doMock('../packages/server/src/local/serve', () => ({
      serveLocalServer,
    }))

    const listeners = new Map<string, (...args: unknown[]) => void>()
    const onSpy = vi.spyOn(process, 'on').mockImplementation(((event, listener) => {
      listeners.set(String(event), listener as (...args: unknown[]) => void)
      return process
    }) as typeof process.on)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined as never) as typeof process.exit)

    const configModule = await import('../packages/server/src/local/config')
    const runtime = await import('../packages/server/src/local/runtime')
    const paths = configModule.localAgentPwPaths(homeDir)

    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }

    expect(await runtime.serveLocalServerProcess(config, '127.0.0.1', paths)).toEqual({ ok: true })
    expect(configModule.readLocalPid(paths)).toBe(process.pid)
    expect(serveLocalServer).toHaveBeenCalledWith(config, '127.0.0.1')
    expect(onSpy).toHaveBeenCalledTimes(3)

    listeners.get('exit')?.()
    expect(configModule.readLocalPid(paths)).toBeNull()

    writeLocalPid(process.pid, paths)
    listeners.get('SIGTERM')?.()
    expect(configModule.readLocalPid(paths)).toBeNull()
    expect(exitSpy).toHaveBeenCalledWith(0)
  })

  it('does not leave a pid file behind when startup fails', async () => {
    const homeDir = createTempHome()
    vi.resetModules()

    const serveLocalServer = vi.fn().mockRejectedValue(new Error('Failed to start server. Is port 9315 in use?'))
    vi.doMock('../packages/server/src/local/serve', () => ({
      serveLocalServer,
    }))

    const configModule = await import('../packages/server/src/local/config')
    const runtime = await import('../packages/server/src/local/runtime')
    const paths = configModule.localAgentPwPaths(homeDir)

    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: paths.dataDir,
    }

    await expect(runtime.serveLocalServerProcess(config, '127.0.0.1', paths)).rejects.toThrow(
      'Failed to start server. Is port 9315 in use?',
    )
    expect(configModule.readLocalPid(paths)).toBeNull()
  })
})

describe('local serve wrapper', () => {
  it('creates the app and serves it with the local base url', async () => {
    vi.resetModules()
    vi.doUnmock('../packages/server/src/local/serve')

    const createLocalDb = vi.fn().mockResolvedValue('db-handle')
    const migrateLocal = vi.fn().mockResolvedValue(undefined)
    const createCoreApp = vi.fn(() => ({ fetch: vi.fn() }))
    const server = new EventEmitter()
    const nodeServe = vi.fn().mockImplementation((_options, onListening) => {
      queueMicrotask(() => {
        onListening?.({ port: 9315 })
      })
      return server
    })

    vi.doMock('../packages/server/src/db/index', () => ({
      createLocalDb,
    }))
    vi.doMock('../packages/server/src/db/migrate-local', () => ({
      migrateLocal,
    }))
    vi.doMock('../packages/server/src/core/app', () => ({
      createCoreApp,
    }))
    vi.doMock('@hono/node-server', () => ({
      serve: nodeServe,
    }))

    const serveModule = await import('../packages/server/src/local/serve')
    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: '/tmp/agentpw-data',
    }

    const app = await serveModule.createLocalServerApp(config)
    expect(app).toEqual({ fetch: expect.any(Function) })
    expect(createLocalDb).toHaveBeenCalledWith('/tmp/agentpw-data')
    expect(migrateLocal).toHaveBeenCalledWith('db-handle')
    expect(createCoreApp).toHaveBeenCalledWith({
      db: 'db-handle',
      biscuitPrivateKey: 'test-private-key',
      baseUrl: 'http://127.0.0.1:9315',
    })

    expect(await serveModule.serveLocalServer(config, '127.0.0.1')).toBe(server)
    expect(nodeServe).toHaveBeenCalledWith({
      fetch: expect.any(Function),
      port: 9315,
      hostname: '127.0.0.1',
    }, expect.any(Function))
  })

  it('surfaces listen failures before reporting success', async () => {
    vi.resetModules()
    vi.doUnmock('../packages/server/src/local/serve')

    const createLocalDb = vi.fn().mockResolvedValue('db-handle')
    const migrateLocal = vi.fn().mockResolvedValue(undefined)
    const createCoreApp = vi.fn(() => ({ fetch: vi.fn() }))
    const server = new EventEmitter()
    const nodeServe = vi.fn().mockImplementation(() => {
      queueMicrotask(() => {
        server.emit('error', Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' }))
      })
      return server
    })

    vi.doMock('../packages/server/src/db/index', () => ({
      createLocalDb,
    }))
    vi.doMock('../packages/server/src/db/migrate-local', () => ({
      migrateLocal,
    }))
    vi.doMock('../packages/server/src/core/app', () => ({
      createCoreApp,
    }))
    vi.doMock('@hono/node-server', () => ({
      serve: nodeServe,
    }))

    const serveModule = await import('../packages/server/src/local/serve')
    const config = {
      biscuitPrivateKey: 'test-private-key',
      masterToken: 'apw_root',
      port: 9315,
      dataDir: '/tmp/agentpw-data',
    }

    await expect(serveModule.serveLocalServer(config, '127.0.0.1')).rejects.toThrow(
      'Failed to start server. Is port 9315 in use?',
    )
  })
})
