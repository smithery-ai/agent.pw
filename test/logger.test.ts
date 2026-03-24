import { afterEach, describe, expect, it, vi } from 'vitest'
import { createLogger } from '../packages/server/src/lib/logger'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('createLogger', () => {
  it('serializes log payloads, messages, bindings, and errors', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const { logger } = createLogger('agentpw')
    const child = logger.child({ requestId: 'req_123' })

    logger.info('hello world')
    logger.info({ status: 200 })
    child.warn({ error: new Error('boom') }, 'warned')
    child.error({ status: 500 }, 'failed')
    child.debug({ scope: 'proxy' }, 'debugging')

    const entries = consoleSpy.mock.calls.map(([line]) => JSON.parse(line as string))
    expect(entries[0]).toEqual(expect.objectContaining({
      level: 'info',
      service: 'agentpw',
      msg: 'hello world',
    }))
    expect(entries[1]).toEqual(expect.objectContaining({
      level: 'info',
      service: 'agentpw',
      status: 200,
      msg: '',
    }))
    expect(entries[2]).toEqual(expect.objectContaining({
      level: 'warn',
      requestId: 'req_123',
      msg: 'warned',
      error: expect.objectContaining({ message: 'boom', name: 'Error' }),
    }))
    expect(entries[3]).toEqual(expect.objectContaining({
      level: 'error',
      requestId: 'req_123',
      status: 500,
      msg: 'failed',
    }))
    expect(entries[4]).toEqual(expect.objectContaining({
      level: 'debug',
      requestId: 'req_123',
      scope: 'proxy',
      msg: 'debugging',
    }))
  })
})
