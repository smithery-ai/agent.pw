import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../packages/cli/src/http', () => ({
  request: vi.fn(),
  requestJson: vi.fn(),
  requestPage: vi.fn(),
  requestAllPages: vi.fn(),
}))

vi.mock('../packages/cli/src/output', () => ({
  output: vi.fn(() => true),
  outputList: vi.fn(() => true),
  outputListPage: vi.fn(() => true),
}))

import { listCreds } from '../packages/cli/src/commands/cred'
import { listProfiles } from '../packages/cli/src/commands/profile'
import * as http from '../packages/cli/src/http'

describe('CLI list pagination', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(http.requestPage).mockResolvedValue({
      data: [],
      hasMore: false,
      nextCursor: null,
    })
    vi.mocked(http.requestAllPages).mockResolvedValue([])
  })

  it('lists profiles one page at a time by default', async () => {
    await listProfiles({ limit: 5, cursor: 'cursor-1' })

    expect(http.requestPage).toHaveBeenCalledWith('/cred_profiles?limit=5&cursor=cursor-1')
    expect(http.requestAllPages).not.toHaveBeenCalled()
  })

  it('lists credentials one page at a time by default', async () => {
    await listCreds({ limit: 5, cursor: 'cursor-2' })

    expect(http.requestPage).toHaveBeenCalledWith('/credentials?limit=5&cursor=cursor-2')
    expect(http.requestAllPages).not.toHaveBeenCalled()
  })

  it('fetches all profile pages only when --all is requested', async () => {
    await listProfiles({ all: true, limit: 25 })

    expect(http.requestAllPages).toHaveBeenCalledWith('/cred_profiles?limit=25')
    expect(http.requestPage).not.toHaveBeenCalled()
  })

  it('fetches all credential pages only when --all is requested', async () => {
    await listCreds({ all: true, limit: 25 })

    expect(http.requestAllPages).toHaveBeenCalledWith('/credentials?limit=25')
    expect(http.requestPage).not.toHaveBeenCalled()
  })
})
