import { describe, expect, it } from 'vitest'
import { openAPIDocumentation, allSchemas } from '../packages/server/src/openapi'

describe('openapi exports', () => {
  it('defines the published API metadata and schema registry', () => {
    expect(openAPIDocumentation).toEqual(expect.objectContaining({
      openapi: '3.1.0',
      info: expect.objectContaining({
        title: 'agent.pw API',
        version: '1.0.0',
      }),
      security: [{ bearerAuth: [] }],
    }))
    expect(openAPIDocumentation.tags.map(tag => tag.name)).toEqual([
      'health',
      'cred_profiles',
      'credentials',
      'tokens',
      'proxy',
      'auth',
    ])
    expect(allSchemas.length).toBeGreaterThan(5)
  })
})
