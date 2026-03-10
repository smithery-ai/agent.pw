import { describe, expect, it } from 'vitest'
import { isDnsError } from '@agent.pw/server/dns'

describe('isDnsError', () => {
  it('recognizes common DNS resolution failures', () => {
    expect(isDnsError(new Error('getaddrinfo ENOTFOUND api.example.com'))).toBe(true)
    expect(isDnsError(new Error('name resolution failed'))).toBe(true)
    expect(isDnsError(new Error('could not resolve host'))).toBe(true)
    expect(isDnsError(new TypeError('fetch failed'))).toBe(true)
  })

  it('ignores unrelated errors and non-error values', () => {
    expect(isDnsError(new Error('socket hang up'))).toBe(false)
    expect(isDnsError('getaddrinfo ENOTFOUND')).toBe(false)
  })
})
