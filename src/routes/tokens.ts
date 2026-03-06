import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import { getPublicKeyHex, getRevocationIds } from '../biscuit'
import { revokeToken } from '../db/queries'
import { errorMessage } from '../lib/utils'

export const RevokeTokenRequestSchema = z.object({
  reason: z.string().optional().meta({ description: 'Reason for revoking the token' }),
}).meta({ id: 'RevokeTokenRequest' })

export const RevokeTokenResponseSchema = z.object({
  ok: z.literal(true),
  revokedIds: z.array(z.string()).meta({ description: 'List of revoked token block IDs' }),
}).meta({ id: 'RevokeTokenResponse' })

export const tokenRoutes = new Hono<CoreHonoEnv>()

tokenRoutes.post('/revoke', requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'Revoke token',
    description: 'Revoke the current bearer token, preventing further use.',
    responses: {
      200: { description: 'Token revoked', content: { 'application/json': { schema: resolver(RevokeTokenResponseSchema) } } },
      400: { description: 'Revocation failed', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'TokenError' })) } } },
    },
  }),
  zValidator('json', RevokeTokenRequestSchema),
  async c => {
    try {
      const db = c.get('db')
      const token = c.get('token') as string
      const body = c.req.valid('json')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const revIds = getRevocationIds(token, publicKeyHex)
      for (const id of revIds) {
        await revokeToken(db, id, body.reason)
      }
      return c.json({ ok: true as const, revokedIds: revIds })
    } catch (e) {
      return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
    }
  },
)
