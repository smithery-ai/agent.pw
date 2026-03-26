import { describe, expect, it } from 'vitest'
import { coerceSqlNamespace, createAgentPwSchema } from 'agent.pw/sql'
import { errorOf, must } from './support/results'

describe('sql namespace helpers', () => {
  it('uses the default namespace when none is provided', () => {
    expect(must(coerceSqlNamespace())).toEqual(expect.objectContaining({
      schema: 'agentpw',
      tablePrefix: '',
    }))
  })

  it('accepts raw options and prebuilt namespace objects', () => {
    const fromOptions = must(coerceSqlNamespace({
      schema: 'connect_data',
      tablePrefix: 'smithery_',
    }))
    expect(fromOptions).toEqual(expect.objectContaining({
      schema: 'connect_data',
      tablePrefix: 'smithery_',
    }))
    expect(fromOptions.tableName('cred_profiles')).toBe('smithery_cred_profiles')

    const prebuilt = must(createAgentPwSchema({
      schema: 'connect_data',
      tablePrefix: 'smithery_',
    }))
    expect(must(coerceSqlNamespace(prebuilt))).toBe(prebuilt)
  })

  it('rejects invalid schema identifiers and table prefixes', () => {
    expect(errorOf(createAgentPwSchema({ schema: 'bad-schema' })).message).toBe(
      "Invalid SQL schema 'bad-schema'",
    )
    expect(errorOf(createAgentPwSchema({ tablePrefix: 'bad-prefix-' })).message).toBe(
      "Invalid table prefix 'bad-prefix-'",
    )
  })
})
