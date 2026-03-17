import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  requestJson,
  resolve,
  spawn,
} = vi.hoisted(() => ({
  requestJson: vi.fn(),
  resolve: vi.fn(),
  spawn: vi.fn(),
}))

vi.mock('node:child_process', () => ({
  spawn,
}))

vi.mock('../packages/cli/src/http', () => ({
  requestJson,
}))

vi.mock('../packages/cli/src/resolve', () => ({
  resolve,
}))

class ExitError extends Error {
  code: number | undefined

  constructor(code: number | undefined) {
    super(`process.exit(${code})`)
    this.code = code
  }
}

type MockChildProcess = EventEmitter & {
  killed: boolean
  kill(signal?: NodeJS.Signals): boolean
}

function createMockChildProcess(
  exitCode: number | null = 0,
  signal: NodeJS.Signals | null = null,
) {
  const child = new EventEmitter() as MockChildProcess
  child.killed = false
  child.kill = vi.fn((nextSignal?: NodeJS.Signals) => {
    if (nextSignal) {
      child.killed = true
    }
    return true
  })

  queueMicrotask(() => {
    child.emit('exit', exitCode, signal)
  })

  return child
}

describe('CLI wrap command', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resolve.mockResolvedValue({
      url: 'http://127.0.0.1:9315',
      token: 'apw_root',
    })
    requestJson.mockResolvedValue({ token: 'apw_child' })
    spawn.mockImplementation(() => createMockChildProcess())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('uses the loopback proxy directly when no restrictions are requested', async () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
      throw new ExitError(code)
    })
    const { wrap } = await import('../packages/cli/src/commands/wrap')

    await expect(wrap(['echo', 'hello'], {})).rejects.toMatchObject({ code: 0 })

    expect(exitSpy).toHaveBeenCalledWith(0)
    expect(requestJson).not.toHaveBeenCalled()
    expect(spawn).toHaveBeenCalledWith('echo', ['hello'], {
      stdio: 'inherit',
      env: expect.objectContaining({
        HTTP_PROXY: 'http://127.0.0.1:9315/',
        HTTPS_PROXY: 'http://127.0.0.1:9315/',
        NO_PROXY: expect.stringContaining('127.0.0.1'),
        no_proxy: expect.stringContaining('localhost'),
      }),
    })
  })

  it('mints a restricted token and embeds it in the proxy URL when constraints are provided', async () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: number) => {
      throw new ExitError(code)
    })
    const { wrap } = await import('../packages/cli/src/commands/wrap')

    await expect(wrap(['env'], {
      services: ['api.github.com'],
      methods: ['get', 'post'],
      paths: ['/user', '/repos'],
      ttl: '5m',
    })).rejects.toMatchObject({ code: 0 })

    expect(exitSpy).toHaveBeenCalledWith(0)
    expect(requestJson).toHaveBeenCalledWith('/tokens/restrict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        constraints: [{
          services: 'api.github.com',
          methods: ['GET', 'POST'],
          paths: ['/user', '/repos'],
          ttl: '5m',
        }],
      }),
    })
    expect(spawn).toHaveBeenCalledWith('env', [], {
      stdio: 'inherit',
      env: expect.objectContaining({
        HTTP_PROXY: 'http://_:apw_child@127.0.0.1:9315/',
        HTTPS_PROXY: 'http://_:apw_child@127.0.0.1:9315/',
      }),
    })
  })
})
