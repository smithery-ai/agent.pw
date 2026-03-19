import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const {
  readCliConfig,
  readTokenStack,
  writeTokenStack,
} = vi.hoisted(() => ({
  readCliConfig: vi.fn(),
  readTokenStack: vi.fn(),
  writeTokenStack: vi.fn(),
}))

vi.mock('../packages/cli/src/config', () => ({
  readCliConfig,
  readTokenStack,
  writeTokenStack,
}))

import { runCli } from '../packages/cli/src/index'
import { popTokenCmd, pushProvidedTokenCmd } from '../packages/cli/src/commands/token'

describe('CLI token stack commands', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    readCliConfig.mockReturnValue({
      url: 'http://localhost:9315',
      token: 'apw_root_token',
    })
    readTokenStack.mockReturnValue([])
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('pushes a provided token onto the stack for temporary use', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    pushProvidedTokenCmd('apw_test_token')

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_test_token'])
    expect(log).toHaveBeenCalledWith(
      'Pushed provided token (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })

  it('pops back to the previous token after a temporary use', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    readTokenStack.mockReturnValue(['apw_root_token', 'apw_temp_token'])

    popTokenCmd()

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_root_token'])
    expect(log).toHaveBeenCalledWith('Popped token (stack depth: 1)')
  })

  it('routes `token push <token>` through the provided-token stack flow', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})

    await runCli(['node', 'agent.pw', 'token', 'push', 'apw_cli_token'])

    expect(writeTokenStack).toHaveBeenCalledWith(['apw_cli_token'])
    expect(log).toHaveBeenCalledWith(
      'Pushed provided token (stack depth: 1). Run `agent.pw token pop` to restore the previous token.',
    )
  })
})
