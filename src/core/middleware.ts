import type { Context, Next } from 'hono'
import type { CoreHonoEnv } from './types'
import { extractBearerToken } from '../proxy'
import {
  authorizeRequest,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
} from '../biscuit'
import { isRevoked } from '../db/queries'

export async function requireToken(c: Context<CoreHonoEnv>, next: Next) {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

  try {
    const revIds = getRevocationIds(token, publicKeyHex)
    const db = c.get('db')
    for (const id of revIds) {
      if (await isRevoked(db, id)) {
        return c.json({ error: 'Token has been revoked' }, 403)
      }
    }
  } catch {
    return c.json({ error: 'Invalid token' }, 401)
  }

  // Run Biscuit authorizer to enforce attenuation checks (TTL, service restrictions).
  // Uses "_management" as resource so service-attenuated tokens are rejected here.
  const authResult = authorizeRequest(token, publicKeyHex, '_management', c.req.method, c.req.path)
  if (!authResult.authorized) {
    return c.json({ error: 'Forbidden', details: authResult.error }, 403)
  }

  const facts = extractTokenFacts(token, publicKeyHex)
  c.set('tokenFacts', facts)
  c.set('token', token)

  return next()
}

export function requireRight(right: string) {
  return async (c: Context<CoreHonoEnv>, next: Next) => {
    const facts = c.get('tokenFacts')
    if (!facts || !facts.rights.includes(right)) {
      return c.json({ error: `Forbidden: requires "${right}" right` }, 403)
    }
    return next()
  }
}

/**
 * Resolves userId from the token's identity and sets it on context.
 * - Admin tokens (right("admin")): can act as any user via ?user= param
 * - Regular tokens: userId from user() fact, rejects ?user= override
 * Must be used after `requireToken`.
 */
export async function resolveUserId(c: Context<CoreHonoEnv>, next: Next) {
  const facts = c.get('tokenFacts')
  if (!facts) return c.json({ error: 'Forbidden' }, 403)

  if (facts.rights.includes('admin')) {
    c.set('userId', c.req.query('user') ?? facts.userId ?? 'local')
  } else if (facts.userId) {
    const userParam = c.req.query('user')
    if (userParam && userParam !== facts.userId) {
      return c.json({ error: 'Forbidden' }, 403)
    }
    c.set('userId', facts.userId)
  } else {
    return c.json({ error: 'No identity in token' }, 403)
  }
  return next()
}
