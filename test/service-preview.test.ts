import { describe, expect, it } from 'vitest'
import { inferServiceIconPreview } from '@agent.pw/server/service-preview'

describe('inferServiceIconPreview', () => {
  it('normalizes known hostnames and uses icon overrides', () => {
    expect(inferServiceIconPreview(' API.GitHub.com:443 ')).toEqual({
      source: 'hostname-favicon',
      host: 'github.com',
      url: 'https://icons.duckduckgo.com/ip3/github.com.ico',
      fallback: 'GH',
    })
  })

  it('derives a monogram from display names for unknown hosts', () => {
    expect(inferServiceIconPreview('api.internal.example.com', 'My Service')).toEqual({
      source: 'hostname-favicon',
      host: 'internal.example.com',
      url: 'https://icons.duckduckgo.com/ip3/internal.example.com.ico',
      fallback: 'MS',
    })
  })

  it('falls back to hostname-derived or generic monograms', () => {
    expect(inferServiceIconPreview('api.openai.dev', 'OpenAI')).toEqual({
      source: 'hostname-favicon',
      host: 'openai.dev',
      url: 'https://icons.duckduckgo.com/ip3/openai.dev.ico',
      fallback: 'OP',
    })
    expect(inferServiceIconPreview('gateway.foobar.dev')).toEqual({
      source: 'hostname-favicon',
      host: 'foobar.dev',
      url: 'https://icons.duckduckgo.com/ip3/foobar.dev.ico',
      fallback: 'FO',
    })
    expect(inferServiceIconPreview('   ')).toEqual({
      source: 'hostname-favicon',
      host: '',
      url: 'https://icons.duckduckgo.com/ip3/.ico',
      fallback: 'API',
    })
    expect(inferServiceIconPreview('api.empty.dev', '!!!')).toEqual({
      source: 'hostname-favicon',
      host: 'empty.dev',
      url: 'https://icons.duckduckgo.com/ip3/empty.dev.ico',
      fallback: 'API',
    })
  })
})
