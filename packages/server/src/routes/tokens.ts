import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import { getPublicKeyHex, getRevocationIds, restrictToken } from '../biscuit'
import { revokeToken } from '../db/queries'
import { errorMessage } from '../lib/utils'

export const RevokeTokenRequestSchema = z.object({
  reason: z.string().optional().meta({ description: 'Reason for revoking the token' }),
}).meta({ id: 'RevokeTokenRequest' })

export const RevokeTokenResponseSchema = z.object({
  ok: z.literal(true),
  revokedIds: z.array(z.string()).meta({ description: 'List of revoked token block IDs' }),
}).meta({ id: 'RevokeTokenResponse' })

const MethodSchema = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
const ConstraintValueSchema = z.union([z.string(), z.array(z.string())])
const MethodValueSchema = z.union([MethodSchema, z.array(MethodSchema)])

export const RestrictTokenRequestSchema = z.object({
  constraints: z.array(z.object({
    services: ConstraintValueSchema.optional(),
    methods: MethodValueSchema.optional(),
    paths: ConstraintValueSchema.optional(),
    ttl: z.union([z.string(), z.number()]).optional(),
  })).min(1).meta({ description: 'Attenuation constraints to append to the current token' }),
}).meta({ id: 'RestrictTokenRequest' })

export const RestrictTokenResponseSchema = z.object({
  ok: z.literal(true),
  token: z.string().meta({ description: 'Restricted child token' }),
}).meta({ id: 'RestrictTokenResponse' })

export const tokenRoutes = new Hono<CoreHonoEnv>()

tokenRoutes.post('/restrict', requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'Restrict token',
    description: 'Create an attenuated child token from the current bearer token.',
    responses: {
      200: { description: 'Restricted token minted', content: { 'application/json': { schema: resolver(RestrictTokenResponseSchema) } } },
      400: { description: 'Restriction failed', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'TokenRestrictError' })) } } },
    },
  }),
  zValidator('json', RestrictTokenRequestSchema),
  async c => {
    try {
      const token = c.get('token') as string
      const body = c.req.valid('json')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const restricted = restrictToken(token, publicKeyHex, body.constraints)
      return c.json({ ok: true as const, token: restricted })
    } catch (e) {
      return c.json({ error: `Failed to restrict token: ${errorMessage(e)}` }, 400)
    }
  },
)

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
