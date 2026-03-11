import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../packages/cli/src/http', () => ({
  getClient: vi.fn(),
  pageToPaginatedResponse: vi.fn(),
  collectAllPages: vi.fn(),
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
  const profilesList = vi.fn()
  const credentialsList = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(http.getClient).mockResolvedValue({
      profiles: { list: profilesList },
      credentials: { list: credentialsList },
    } as never)
    vi.mocked(http.pageToPaginatedResponse).mockResolvedValue({
      data: [],
      hasMore: false,
      nextCursor: null,
    })
    vi.mocked(http.collectAllPages).mockResolvedValue([])
  })

  it('lists profiles one page at a time by default', async () => {
    await listProfiles({ limit: 5, cursor: 'cursor-1' })

    expect(profilesList).toHaveBeenCalledWith({ limit: 5, cursor: 'cursor-1' })
    expect(http.pageToPaginatedResponse).toHaveBeenCalled()
    expect(http.collectAllPages).not.toHaveBeenCalled()
  })

  it('lists credentials one page at a time by default', async () => {
    await listCreds({ limit: 5, cursor: 'cursor-2' })

    expect(credentialsList).toHaveBeenCalledWith({ limit: 5, cursor: 'cursor-2' })
    expect(http.pageToPaginatedResponse).toHaveBeenCalled()
    expect(http.collectAllPages).not.toHaveBeenCalled()
  })

  it('fetches all profile pages only when --all is requested', async () => {
    await listProfiles({ all: true, limit: 25 })

    expect(profilesList).toHaveBeenCalledWith({ limit: 25 })
    expect(http.collectAllPages).toHaveBeenCalled()
    expect(http.pageToPaginatedResponse).not.toHaveBeenCalled()
  })

  it('fetches all credential pages only when --all is requested', async () => {
    await listCreds({ all: true, limit: 25 })

    expect(credentialsList).toHaveBeenCalledWith({ limit: 25 })
    expect(http.collectAllPages).toHaveBeenCalled()
    expect(http.pageToPaginatedResponse).not.toHaveBeenCalled()
  })
})
