import { describe, expect, it } from 'vitest'
import {
  DEFAULT_API_KEY_SCHEME,
  getApiKeyScheme,
  getOAuthScheme,
  parseAuthSchemes,
} from '@agent.pw/server/auth-schemes'

describe('auth schemes', () => {
  it('parses valid auth schemes and applies defaults', () => {
    expect(parseAuthSchemes(JSON.stringify([{ type: 'apiKey' }]))).toEqual([
      { type: 'apiKey', in: 'header', name: 'Authorization' },
    ])
    expect(parseAuthSchemes(JSON.stringify([{ type: 'http', scheme: 'basic' }]))).toEqual([
      { type: 'http', scheme: 'basic' },
    ])
  })

  it('returns an empty list for null or invalid input', () => {
    expect(parseAuthSchemes(null)).toEqual([])
    expect(parseAuthSchemes('not json')).toEqual([])
    expect(parseAuthSchemes(JSON.stringify([{ type: 'nope' }]))).toEqual([])
  })

  it('picks api key or http schemes and finds oauth schemes when present', () => {
    const schemes = parseAuthSchemes(JSON.stringify([
      { type: 'http', scheme: 'bearer' },
      { type: 'oauth2', authorizeUrl: 'https://example.com/auth', tokenUrl: 'https://example.com/token', scopes: 'repo' },
      { type: 'apiKey', in: 'header', name: 'X-Api-Key' },
    ]))

    expect(getApiKeyScheme(schemes)).toEqual({ type: 'apiKey', in: 'header', name: 'X-Api-Key' })
    expect(getApiKeyScheme([{ type: 'http', scheme: 'basic' }])).toEqual({ type: 'http', scheme: 'basic' })
    expect(getOAuthScheme(schemes)).toEqual({
      type: 'oauth2',
      authorizeUrl: 'https://example.com/auth',
      tokenUrl: 'https://example.com/token',
      scopes: 'repo',
    })
    expect(getOAuthScheme([DEFAULT_API_KEY_SCHEME])).toBeUndefined()
  })
})
