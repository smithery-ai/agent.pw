import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import {
  injectSchemas,
  replaceInlineSchemasWithRefs,
  rewriteRefs,
} from '../packages/server/src/lib/openapi-utils'
import { AuthScheme } from '@agent.pw/server/auth-schemes'

describe('openapi utils', () => {
  it('injects zod schemas into components and rewrites inline schemas to refs', () => {
    const Metadata = z.record(z.string(), z.string()).meta({ id: 'Metadata' })
    const Inline = z.object({
      ok: z.boolean(),
      auth: AuthScheme,
    }).meta({ id: 'Inline' })

    const spec: Record<string, unknown> = {
      paths: {
        '/health': {
          get: {
            responses: {
              '200': {
                content: {
                  'application/json': {
                    schema: { id: 'Inline', type: 'object' },
                  },
                },
              },
            },
          },
        },
      },
    }

    injectSchemas(spec, [Metadata, Inline], { ambiguousSchemas: new Set(['Metadata']) })

    const components = (spec.components as { schemas: Record<string, any> }).schemas
    expect(components.Metadata.additionalProperties['x-stainless-any']).toBe(true)
    expect(components.AuthScheme).toBeDefined()
    expect(components.ApiKeyScheme).toBeDefined()
    expect(components.HttpScheme).toBeDefined()
    expect(components.OAuth2Scheme).toBeDefined()
    expect(((spec.paths as any)['/health'].get.responses['200'].content['application/json'].schema)).toEqual({
      $ref: '#/components/schemas/Inline',
    })
  })

  it('rewrites nested refs and inline schemas recursively', () => {
    const obj: Record<string, unknown> = {
      items: [
        { schema: { id: 'Thing' } },
        { $ref: '#/$defs/Nested' },
      ],
    }

    replaceInlineSchemasWithRefs(obj, { Thing: { type: 'object' } })
    rewriteRefs(obj)

    expect(obj).toEqual({
      items: [
        { schema: { $ref: '#/components/schemas/Thing' } },
        { $ref: '#/components/schemas/Nested' },
      ],
    })
  })

  it('skips schemas without ids and no-ops on primitive inputs', () => {
    const spec: Record<string, unknown> = {
      paths: {},
    }

    injectSchemas(spec, [z.object({ ok: z.boolean() })])
    expect(spec).toEqual({
      components: { schemas: {} },
      paths: {},
    })

    replaceInlineSchemasWithRefs(null, {})
    replaceInlineSchemasWithRefs('not-an-object', {})
    rewriteRefs(undefined)
  })
})
