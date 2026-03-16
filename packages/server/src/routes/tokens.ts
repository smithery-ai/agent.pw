import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import { extractTokenFacts, getPublicKeyHex, getRevocationIds, restrictToken } from '../biscuit'
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
    actions: ConstraintValueSchema.optional(),
    hosts: ConstraintValueSchema.optional(),
    roots: ConstraintValueSchema.optional(),
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

export const InspectTokenRequestSchema = z.object({
  token: z.string().meta({ description: 'Token to inspect' }),
}).meta({ id: 'InspectTokenRequest' })

export const InspectTokenResponseSchema = z.object({
  valid: z.literal(true),
  userId: z.string().nullable(),
  orgId: z.string().nullable(),
  rights: z.array(z.object({
    action: z.string(),
    root: z.string(),
  })),
  homePath: z.string().nullable(),
  scopes: z.array(z.string()),
}).meta({ id: 'InspectTokenResponse' })

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
      const token = c.get('token')
      if (!token) return c.json({ error: 'Missing token' }, 401)
      const body = c.req.valid('json')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const restricted = restrictToken(token, publicKeyHex, body.constraints)
      return c.json({ ok: true, token: restricted })
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
      const token = c.get('token')
      if (!token) return c.json({ error: 'Missing token' }, 401)
      const body = c.req.valid('json')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const revIds = getRevocationIds(token, publicKeyHex)
      for (const id of revIds) {
        await revokeToken(db, id, body.reason)
      }
      return c.json({ ok: true, revokedIds: revIds })
    } catch (e) {
      return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
    }
  },
)

tokenRoutes.post('/inspect',
  describeRoute({
    tags: ['tokens'],
    summary: 'Inspect token',
    description: 'Inspect a Biscuit token and return its extracted facts.',
    responses: {
      200: { description: 'Token facts', content: { 'application/json': { schema: resolver(InspectTokenResponseSchema) } } },
      400: { description: 'Token is invalid or unrecognized', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'TokenInspectError' })) } } },
    },
  }),
  zValidator('json', InspectTokenRequestSchema),
  async c => {
    try {
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const body = c.req.valid('json')
      const facts = extractTokenFacts(body.token, publicKeyHex)

      if (!facts.userId && !facts.orgId) {
        return c.json({ error: 'Invalid or unrecognized token' }, 400)
      }

      return c.json({
        valid: true,
        userId: facts.userId,
        orgId: facts.orgId,
        rights: facts.rights,
        homePath: facts.homePath,
        scopes: facts.scopes,
      })
    } catch {
      return c.json({ error: 'Invalid or unrecognized token' }, 400)
    }
  },
)
