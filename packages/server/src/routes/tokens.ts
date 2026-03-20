import { Hono } from 'hono'
import { describeRoute, resolver, validator as zValidator } from 'hono-openapi'
import { z } from 'zod'
import type { CoreHonoEnv, HttpMethod, TokenConstraint, TokenRight } from '../core/types'
import { requireToken } from '../core/middleware'
import {
  extractTokenExpiry,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
  hashToken,
  mintDescendantToken,
} from '../biscuit'
import {
  createIssuedToken,
  getIssuedTokenById,
  listIssuedTokensByOwner,
  revokeIssuedTokenById,
} from '../db/queries'
import { errorMessage, randomId } from '../lib/utils'
import { isAncestorOrEqual, validatePath } from '../paths'

const MethodSchema = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
const ConstraintValueSchema = z.union([z.string(), z.array(z.string())])
const MethodValueSchema = z.union([MethodSchema, z.array(MethodSchema)])

export const TokenRightSchema = z.object({
  action: z.string(),
  root: z.string(),
}).meta({ id: 'TokenRight' })

export const TokenConstraintSchema = z.object({
  actions: ConstraintValueSchema.optional(),
  hosts: ConstraintValueSchema.optional(),
  roots: ConstraintValueSchema.optional(),
  services: ConstraintValueSchema.optional(),
  methods: MethodValueSchema.optional(),
  paths: ConstraintValueSchema.optional(),
  ttl: z.union([z.string(), z.number()]).optional(),
}).meta({ id: 'TokenConstraint' })

export const CreateTokenRequestSchema = z.object({
  name: z.string().trim().min(1).max(200).optional(),
  constraints: z.array(TokenConstraintSchema).optional(),
}).meta({ id: 'CreateTokenRequest' })

export const InspectTokenRequestSchema = z.object({
  token: z.string().meta({ description: 'Token to inspect' }),
}).meta({ id: 'InspectTokenRequest' })

export const InspectTokenResponseSchema = z.object({
  valid: z.literal(true),
  userId: z.string().nullable(),
  orgId: z.string().nullable(),
  rights: z.array(TokenRightSchema),
  homePath: z.string().nullable(),
  scopes: z.array(z.string()),
}).meta({ id: 'InspectTokenResponse' })

export const IssuedTokenSchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  rights: z.array(TokenRightSchema),
  constraints: z.array(TokenConstraintSchema),
  createdAt: z.string(),
  expiresAt: z.string().nullable(),
  lastUsedAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
  revokeReason: z.string().nullable(),
}).meta({ id: 'IssuedToken' })

export const IssuedTokenListResponseSchema = z.object({
  data: z.array(IssuedTokenSchema),
}).meta({ id: 'IssuedTokenListResponse' })

export const CreateTokenResponseSchema = IssuedTokenSchema.extend({
  ok: z.literal(true),
  token: z.string(),
}).meta({ id: 'CreateTokenResponse' })

export const RevokeTokenRequestSchema = z.object({
  reason: z.string().optional().meta({ description: 'Reason for revoking the token' }),
}).meta({ id: 'RevokeTokenRequest' })

export const RevokeTokenResponseSchema = z.object({
  ok: z.literal(true),
  id: z.string(),
  revokedAt: z.string().nullable(),
  revokedIds: z.array(z.string()).meta({ description: 'List of revoked token block IDs' }),
}).meta({ id: 'RevokeTokenResponse' })

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function uniqueRights(rights: TokenRight[]) {
  const seen = new Set<string>()
  return rights.filter(right => {
    const key = `${right.action}:${right.root}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function normalizeMethod(method: string): HttpMethod {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'GET'
    case 'POST':
      return 'POST'
    case 'PUT':
      return 'PUT'
    case 'DELETE':
      return 'DELETE'
    case 'PATCH':
      return 'PATCH'
    case 'HEAD':
      return 'HEAD'
    case 'OPTIONS':
      return 'OPTIONS'
    default:
      throw new Error(`Invalid method '${method}'`)
  }
}

function normalizeConstraint(constraint: z.infer<typeof TokenConstraintSchema>): TokenConstraint {
  const actions = toArray(constraint.actions).filter(Boolean)
  const hosts = toArray(constraint.hosts).filter(Boolean)
  const roots = toArray(constraint.roots).filter(Boolean)
  const services = toArray(constraint.services).filter(Boolean)
  const methods = toArray(constraint.methods).filter(Boolean).map(normalizeMethod)
  const paths = toArray(constraint.paths).filter(Boolean)

  for (const root of roots) {
    if (!validatePath(root)) {
      throw new Error(`Invalid root '${root}'`)
    }
  }

  const normalized: TokenConstraint = {}
  if (actions.length > 0) normalized.actions = actions.length === 1 ? actions[0] : actions
  if (hosts.length > 0) normalized.hosts = hosts.length === 1 ? hosts[0] : hosts
  if (roots.length > 0) normalized.roots = roots.length === 1 ? roots[0] : roots
  if (services.length > 0) normalized.services = services.length === 1 ? services[0] : services
  if (methods.length > 0) normalized.methods = methods.length === 1 ? methods[0] : methods
  if (paths.length > 0) normalized.paths = paths.length === 1 ? paths[0] : paths
  if (constraint.ttl !== undefined) normalized.ttl = constraint.ttl
  return normalized
}

function normalizeConstraints(constraints: z.infer<typeof TokenConstraintSchema>[] | undefined): TokenConstraint[] {
  return (constraints ?? []).map(normalizeConstraint)
}

function deriveChildRights(parentRights: TokenRight[], constraints: TokenConstraint[]) {
  if (constraints.length === 0) {
    return uniqueRights(parentRights)
  }

  const childRights: TokenRight[] = []
  const parentActions = [...new Set(parentRights.map(right => right.action))]

  for (const constraint of constraints) {
    const actions = toArray(constraint.actions)
    const roots = toArray(constraint.roots)

    if (actions.length === 0 && roots.length === 0) {
      childRights.push(...parentRights)
      continue
    }

    if (actions.length > 0 && roots.length === 0) {
      for (const action of actions) {
        const matches = parentRights.filter(right => right.action === action)
        if (matches.length === 0) {
          throw new Error(`Parent token cannot grant ${action}`)
        }
        childRights.push(...matches)
      }
      continue
    }

    if (actions.length === 0) {
      for (const root of roots) {
        let matched = false
        for (const action of parentActions) {
          if (!parentRights.some(right => right.action === action && isAncestorOrEqual(right.root, root))) {
            continue
          }
          childRights.push({ action, root })
          matched = true
        }
        if (!matched) {
          throw new Error(`Requested root '${root}' exceeds parent token scope`)
        }
      }
      continue
    }

    for (const root of roots) {
      for (const action of actions) {
        if (!parentRights.some(right => right.action === action && isAncestorOrEqual(right.root, root))) {
          throw new Error(`Requested root '${root}' exceeds parent token scope for ${action}`)
        }
        childRights.push({ action, root })
      }
    }
  }

  return uniqueRights(childRights)
}

function ownerForFacts(facts: NonNullable<CoreHonoEnv['Variables']['tokenFacts']>) {
  return {
    ownerUserId: facts.userId ?? null,
    orgId: facts.orgId ?? null,
  }
}

function hasManageRight(facts: NonNullable<CoreHonoEnv['Variables']['tokenFacts']>) {
  return facts.rights.some(right => right.action === 'credential.manage')
}

function serializeIssuedToken(row: {
  id: string
  name: string | null
  rights: TokenRight[]
  constraints: TokenConstraint[]
  createdAt: Date
  expiresAt: Date | null
  lastUsedAt: Date | null
  revokedAt: Date | null
  revokeReason: string | null
}) {
  return {
    id: row.id,
    name: row.name,
    rights: row.rights,
    constraints: row.constraints,
    createdAt: new Date(row.createdAt).toISOString(),
    expiresAt: row.expiresAt ? new Date(row.expiresAt).toISOString() : null,
    lastUsedAt: row.lastUsedAt ? new Date(row.lastUsedAt).toISOString() : null,
    revokedAt: row.revokedAt ? new Date(row.revokedAt).toISOString() : null,
    revokeReason: row.revokeReason,
  }
}

function ensureFacts(c: { get(key: 'tokenFacts'): CoreHonoEnv['Variables']['tokenFacts'] }) {
  const facts = c.get('tokenFacts')
  /* v8 ignore start -- requireToken always populates tokenFacts before these handlers run */
  if (!facts) {
    throw new Error('Missing token facts')
  }
  /* v8 ignore stop */
  return facts
}

export const tokenRoutes = new Hono<CoreHonoEnv>()

tokenRoutes.post('/',
  requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'Issue token',
    description: 'Create a tracked Biscuit token derived from the current bearer token.',
    responses: {
      200: { description: 'Tracked token minted', content: { 'application/json': { schema: resolver(CreateTokenResponseSchema) } } },
      400: { description: 'Token issuance failed', content: { 'application/json': { schema: resolver(z.object({ error: z.string() }).meta({ id: 'TokenCreateError' })) } } },
      403: { description: 'Requested scope exceeds parent token' },
    },
  }),
  zValidator('json', CreateTokenRequestSchema),
  async c => {
    try {
      const db = c.get('db')
      const token = c.get('token')
      const facts = ensureFacts(c)
      if (!token) return c.json({ error: 'Missing token' }, 401)

      const body = c.req.valid('json')
      const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      const normalizedConstraints = normalizeConstraints(body.constraints)
      const rights = deriveChildRights(facts.rights, normalizedConstraints)
      const childToken = mintDescendantToken(
        c.env.BISCUIT_PRIVATE_KEY,
        publicKeyHex,
        token,
        rights,
        normalizedConstraints,
      )
      const revocationIds = getRevocationIds(childToken, publicKeyHex)
      const expiresAt = extractTokenExpiry(childToken, publicKeyHex)
      const row = await createIssuedToken(db, {
        id: randomId(),
        ownerUserId: facts.userId ?? null,
        orgId: facts.orgId ?? null,
        name: body.name ?? null,
        tokenHash: await hashToken(childToken),
        revocationIds,
        rights,
        constraints: normalizedConstraints,
        expiresAt,
      })

      /* v8 ignore start -- insert().returning() either yields the new row or throws */
      if (!row) {
        return c.json({ error: 'Failed to create token record' }, 500)
      }
      /* v8 ignore stop */

      return c.json({
        ok: true,
        token: childToken,
        ...serializeIssuedToken(row),
      })
    } catch (e) {
      const message = errorMessage(e)
      const status = message.includes('exceeds parent token scope') || message.includes('cannot grant')
        ? 403
        : 400
      return c.json({ error: `Failed to create token: ${message}` }, status)
    }
  },
)

tokenRoutes.get('/',
  requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'List issued tokens',
    description: 'List tracked tokens owned by the current token identity.',
    responses: {
      200: { description: 'Tracked tokens', content: { 'application/json': { schema: resolver(IssuedTokenListResponseSchema) } } },
      403: { description: 'Credential management right required' },
    },
  }),
  async c => {
    const facts = ensureFacts(c)
    if (!hasManageRight(facts)) {
      return c.json({ error: 'Forbidden: requires "credential.manage" right' }, 403)
    }

    const rows = await listIssuedTokensByOwner(c.get('db'), ownerForFacts(facts))
    return c.json({
      data: rows.map(serializeIssuedToken),
    })
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
    /* v8 ignore start -- extractTokenFacts returns a sentinel object instead of throwing */
    } catch {
      return c.json({ error: 'Invalid or unrecognized token' }, 400)
    }
    /* v8 ignore stop */
  },
)

tokenRoutes.get('/:id',
  requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'Get issued token',
    description: 'Fetch metadata for one tracked token.',
    responses: {
      200: { description: 'Tracked token', content: { 'application/json': { schema: resolver(IssuedTokenSchema) } } },
      403: { description: 'Credential management right required' },
      404: { description: 'Tracked token not found' },
    },
  }),
  async c => {
    const facts = ensureFacts(c)
    if (!hasManageRight(facts)) {
      return c.json({ error: 'Forbidden: requires "credential.manage" right' }, 403)
    }

    const row = await getIssuedTokenById(c.get('db'), c.req.param('id'), ownerForFacts(facts))
    if (!row) {
      return c.json({ error: 'Issued token not found' }, 404)
    }

    return c.json(serializeIssuedToken(row))
  },
)

tokenRoutes.delete('/:id',
  requireToken,
  describeRoute({
    tags: ['tokens'],
    summary: 'Revoke issued token',
    description: 'Revoke a tracked token by ID.',
    responses: {
      200: { description: 'Tracked token revoked', content: { 'application/json': { schema: resolver(RevokeTokenResponseSchema) } } },
      403: { description: 'Credential management right required' },
      404: { description: 'Tracked token not found' },
    },
  }),
  async c => {
    const facts = ensureFacts(c)
    if (!hasManageRight(facts)) {
      return c.json({ error: 'Forbidden: requires "credential.manage" right' }, 403)
    }

    const parsed = RevokeTokenRequestSchema.safeParse(await c.req.json().catch(() => ({})))
    if (!parsed.success) {
      return c.json({ error: 'Invalid revoke request' }, 400)
    }

    const row = await revokeIssuedTokenById(
      c.get('db'),
      c.req.param('id'),
      ownerForFacts(facts),
      parsed.data.reason,
    )
    if (!row) {
      return c.json({ error: 'Issued token not found' }, 404)
    }

    return c.json({
      ok: true,
      id: row.id,
      revokedAt: row.revokedAt ? new Date(row.revokedAt).toISOString() : null,
      revokedIds: row.revocationIds,
    })
  },
)
