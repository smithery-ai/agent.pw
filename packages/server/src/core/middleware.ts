import type { Context, Next } from 'hono'
import type { CoreHonoEnv } from './types'
import { extractProxyToken, PROXY_TOKEN_HEADER } from '../proxy'
import {
  authorizeRequest,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
} from '../biscuit'
import { isRevoked } from '../db/queries'

export async function requireToken(c: Context<CoreHonoEnv>, next: Next) {
  const token = extractProxyToken(c.req.header(PROXY_TOKEN_HEADER))
  if (!token) {
    return c.json({
      error: `Missing ${PROXY_TOKEN_HEADER} header`,
      hint: `Send your Biscuit token in the ${PROXY_TOKEN_HEADER} header.`,
    }, 401)
  }

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
 * - Admin tokens (right("admin")): can act as any user via Act-As header
 * - Regular tokens: userId from user() fact, rejects Act-As override
 * Must be used after `requireToken`.
 */
export async function resolveUserId(c: Context<CoreHonoEnv>, next: Next) {
  const facts = c.get('tokenFacts')
  if (!facts) return c.json({ error: 'Forbidden' }, 403)

  const actAs = c.req.header('Act-As')
  const resolvedIdentity = facts.userId ?? facts.orgId

  if (facts.rights.includes('admin')) {
    c.set('userId', actAs ?? resolvedIdentity ?? 'local')
  } else if (resolvedIdentity) {
    if (actAs && actAs !== resolvedIdentity) {
      return c.json({ error: 'Forbidden' }, 403)
    }
    c.set('userId', resolvedIdentity)
  } else {
    return c.json({ error: 'No identity in token' }, 403)
  }
  return next()
}
