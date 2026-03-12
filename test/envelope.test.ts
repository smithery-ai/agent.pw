import { describe, expect, it } from 'vitest'
import { buildJwks } from '../packages/server/src/webhooks/envelope'

describe('buildJwks', () => {
  it('converts ed25519 public keys into a JWKS document', () => {
    const hex = 'ed25519/e43c506c0d441f5b4e4ccac8c7572ac5b9d3773a3a95c21584164bec11f0d9ab'
    const jwks = buildJwks(hex)

    expect(jwks).toEqual({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: Buffer.from('e43c506c0d441f5b4e4ccac8c7572ac5b9d3773a3a95c21584164bec11f0d9ab', 'hex').toString('base64url'),
          use: 'sig',
          kid: 'agentpw-ed25519-1',
        },
      ],
    })
  })
})
