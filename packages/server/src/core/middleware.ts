import type { Context, Next } from 'hono'
import type { CoreHonoEnv } from './types'
import { extractBearerToken } from '../proxy'
import {
  authorizeRequest,
  extractTokenExpiry,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
  hashToken,
} from '../biscuit'
import { isRevoked, markIssuedTokenUsed } from '../db/queries'

const MANAGEMENT_TOKEN_HEADER = 'Authorization'

async function validatePresentedToken(
  c: Context<CoreHonoEnv>,
  token: string,
) {
  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

  try {
    const revIds = getRevocationIds(token, publicKeyHex)
    const db = c.get('db')
    for (const id of revIds) {
      if (await isRevoked(db, id)) {
        return { ok: false as const, response: c.json({ error: 'Token has been revoked' }, 403) }
      }
    }
  } catch {
    return { ok: false as const, response: c.json({ error: 'Invalid token' }, 401) }
  }

  const expiresAt = extractTokenExpiry(token, publicKeyHex)
  if (expiresAt && expiresAt.getTime() <= Date.now()) {
    return { ok: false as const, response: c.json({ error: 'Token has expired' }, 403) }
  }

  const facts = extractTokenFacts(token, publicKeyHex)
  if (!facts.userId && !facts.orgId) {
    return { ok: false as const, response: c.json({ error: 'Invalid token' }, 401) }
  }

  c.set('tokenFacts', facts)
  c.set('token', token)

  return { ok: true as const, publicKeyHex }
}

async function trackIssuedTokenUsage(c: Context<CoreHonoEnv>, token: string) {
  const tokenHash = await hashToken(token)
  await markIssuedTokenUsed(c.get('db'), tokenHash)
}

function missingTokenResponse(c: Context<CoreHonoEnv>) {
  return c.json({
    error: `Missing ${MANAGEMENT_TOKEN_HEADER} header`,
    hint: `Send your Biscuit token in the ${MANAGEMENT_TOKEN_HEADER} header. Proxy requests still use Proxy-Authorization.`,
  }, 401)
}

export async function requireValidToken(c: Context<CoreHonoEnv>, next: Next) {
  const token = extractBearerToken(c.req.header(MANAGEMENT_TOKEN_HEADER))
  if (!token) {
    return missingTokenResponse(c)
  }

  const validation = await validatePresentedToken(c, token)
  if (!validation.ok) {
    return validation.response
  }

  await trackIssuedTokenUsage(c, token)
  return next()
}

export async function requireToken(c: Context<CoreHonoEnv>, next: Next) {
  const token = extractBearerToken(c.req.header(MANAGEMENT_TOKEN_HEADER))
  if (!token) {
    return missingTokenResponse(c)
  }

  const validation = await validatePresentedToken(c, token)
  if (!validation.ok) {
    return validation.response
  }

  const { publicKeyHex } = validation

  // Run Biscuit authorizer to enforce attenuation checks (TTL, service restrictions).
  const authResult = authorizeRequest(token, publicKeyHex, '_management', c.req.method, c.req.path, {
    action: '_management',
  })
  if (!authResult.authorized) {
    return c.json({ error: 'Forbidden', details: authResult.error }, 403)
  }

  await trackIssuedTokenUsage(c, token)
  return next()
}

export function requireRight(right: string) {
  return async (c: Context<CoreHonoEnv>, next: Next) => {
    const facts = c.get('tokenFacts')
    if (!facts || !facts.rights.some(tokenRight => tokenRight.action === right)) {
      return c.json({ error: `Forbidden: requires "${right}" right` }, 403)
    }
    return next()
  }
}

/**
 * Resolves userId from the token's identity and sets it on context.
 * Uses the token's user_id() fact when present, otherwise falls back to org identity.
 * Must be used after `requireToken`.
 */
export async function resolveUserId(c: Context<CoreHonoEnv>, next: Next) {
  const facts = c.get('tokenFacts')
  if (!facts) return c.json({ error: 'Forbidden' }, 403)

  const resolvedIdentity = facts.userId ?? facts.orgId

  if (resolvedIdentity) {
    c.set('userId', resolvedIdentity)
  } else {
    return c.json({ error: 'No identity in token' }, 403)
  }
  return next()
}
