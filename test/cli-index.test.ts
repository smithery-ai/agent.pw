import { afterEach, describe, expect, it, vi } from 'vitest'
import { buildProgram, runCli } from '../packages/cli/src/index'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('CLI root onboarding', () => {
  it('prints a quick-start welcome when no command is provided', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw'])

    expect(log).toHaveBeenCalledTimes(1)
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Welcome to agent.pw.'))
    expect(log).toHaveBeenCalledWith(expect.stringContaining('agent.pw lets your AI agent use APIs'))
    expect(log).toHaveBeenCalledWith(expect.stringContaining('npx agent.pw start'))
    expect(log).toHaveBeenCalledWith(expect.stringContaining('smithery-ai/agentpw'))
    expect(log).toHaveBeenCalledWith(expect.stringContaining('npx agent.pw --help'))
  })

  it('adds the same quick-start hint to the help output', () => {
    let help = ''
    const program = buildProgram()
    program.configureOutput({
      writeOut: value => {
        help += value
      },
      writeErr: value => {
        help += value
      },
    })
    program.outputHelp()

    expect(help).toContain('New here?')
    expect(help).toContain('npx agent.pw start')
    expect(help).toContain('smithery-ai/agentpw')
    expect(help).toContain('connect your first API')
  })

  it('does not expose browser bootstrap helpers on the public token command surface', () => {
    const tokenCommand = buildProgram().commands.find(command => command.name() === 'token')

    expect(tokenCommand).toBeDefined()
    expect(tokenCommand?.commands.map(command => command.name())).toContain('push')
    expect(tokenCommand?.commands.map(command => command.name())).not.toContain('bootstrap')
    expect(tokenCommand?.commands.map(command => command.name())).not.toContain('connect-url')
    expect(tokenCommand?.commands.map(command => command.name())).not.toContain('use')
  })
})
