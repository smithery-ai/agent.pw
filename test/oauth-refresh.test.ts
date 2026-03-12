import { afterEach, describe, expect, it, vi } from 'vitest'
import { refreshOAuthToken } from '../packages/server/src/lib/oauth-refresh'

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('refreshOAuthToken', () => {
  it('uses basic auth, parses JSON, and resolves nested token fields', async () => {
    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      expect(headers.get('Content-Type')).toBe('application/x-www-form-urlencoded')
      expect(headers.get('Authorization')).toBe(`Basic ${btoa('client-id:client-secret')}`)

      const body = new URLSearchParams(init?.body as string)
      expect(body.get('grant_type')).toBe('refresh_token')
      expect(body.get('refresh_token')).toBe('refresh-token')
      expect(body.get('scope')).toBe('repo')
      expect(body.get('client_id')).toBeNull()
      expect(body.get('client_secret')).toBeNull()

      return new Response(JSON.stringify({
        data: {
          access: {
            token: 'new-access-token',
          },
        },
        refresh: {
          token: 'new-refresh-token',
        },
        expires_at: '2026-03-10T12:00:00.000Z',
      }), {
        headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      scopes: 'repo',
      authConfig: {
        token_auth: 'basic',
        token_path: 'data.access.token',
        refresh_token_path: 'refresh.token',
      },
    })

    expect(result).toEqual({
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token',
      expiresAt: '2026-03-10T12:00:00.000Z',
    })
  })

  it('uses body auth, parses form responses, and honors accept headers', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-03-10T12:00:00.000Z'))

    const fetchMock = vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      expect(headers.get('Accept')).toBe('application/x-www-form-urlencoded')
      expect(headers.get('Authorization')).toBeNull()

      const body = new URLSearchParams(init?.body as string)
      expect(body.get('client_id')).toBe('client-id')
      expect(body.get('client_secret')).toBe('client-secret')

      return new Response('access_token=form-access&expires_in=300', {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authConfig: {
        token_accept: 'application/x-www-form-urlencoded',
      },
    })

    expect(result).toEqual({
      accessToken: 'form-access',
      refreshToken: 'refresh-token',
      expiresAt: '2026-03-10T12:05:00.000Z',
    })
  })

  it('supports numeric expires_in values and missing expiry metadata', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-03-10T12:00:00.000Z'))

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'numeric-access',
      refresh_token: 'numeric-refresh',
      expires_in: 120,
    }), {
      headers: { 'content-type': 'application/json' },
    })))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
    })).resolves.toEqual({
      accessToken: 'numeric-access',
      refreshToken: 'numeric-refresh',
      expiresAt: '2026-03-10T12:02:00.000Z',
    })

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      access_token: 'no-expiry',
    }), {
      headers: { 'content-type': 'application/json' },
    })))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
    })).resolves.toEqual({
      accessToken: 'no-expiry',
      refreshToken: 'refresh-token',
      expiresAt: undefined,
    })
  })

  it('throws useful errors for failed responses and missing access tokens', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('bad refresh', { status: 400 })))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
    })).rejects.toThrow('Token refresh failed: bad refresh')

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ nope: true }), {
      headers: { 'content-type': 'application/json' },
    })))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
    })).rejects.toThrow('No access token in refresh response')

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      data: 'not-an-object',
    }))))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
      authConfig: {
        token_path: 'data.access.token',
      },
    })).rejects.toThrow('No access token in refresh response')
  })

  it('detects JSON bodies even when the token endpoint omits a content type', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      new TextEncoder().encode('{"access_token":"sniffed-token"}'),
    )))

    await expect(refreshOAuthToken({
      tokenUrl: 'https://example.com/token',
      refreshToken: 'refresh-token',
      clientId: 'client-id',
    })).resolves.toEqual({
      accessToken: 'sniffed-token',
      refreshToken: 'refresh-token',
      expiresAt: undefined,
    })
  })
})
