import { describe, expect, it } from 'vitest'
import { AgentPwConflictError, AgentPwInputError } from '../packages/server/src/errors'

describe('agent.pw errors', () => {
  it('assigns stable error names', () => {
    const conflict = new AgentPwConflictError('conflict')
    const input = new AgentPwInputError('input')

    expect(conflict).toBeInstanceOf(Error)
    expect(conflict.name).toBe('AgentPwConflictError')
    expect(conflict.message).toBe('conflict')

    expect(input).toBeInstanceOf(Error)
    expect(input.name).toBe('AgentPwInputError')
    expect(input.message).toBe('input')
  })
})
