import type { Context, Next } from 'hono'
import type { CoreHonoEnv } from './types'
import { extractBearerToken } from '../proxy'
import {
  extractManagementRights,
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

  const mgmt = extractManagementRights(token, publicKeyHex)
  c.set('managementRights', mgmt)
  c.set('token', token)

  return next()
}

export function requireRight(right: string) {
  return async (c: Context<CoreHonoEnv>, next: Next) => {
    const mgmt = c.get('managementRights')
    if (!mgmt || !mgmt.rights.includes(right)) {
      return c.json({ error: `Forbidden: requires "${right}" right` }, 403)
    }
    return next()
  }
}

export function requireVaultAdmin(paramName: string) {
  return async (c: Context<CoreHonoEnv>, next: Next) => {
    const slug = c.req.param(paramName)
    const mgmt = c.get('managementRights')
    if (!mgmt) return c.json({ error: 'Forbidden' }, 403)
    if (!mgmt.vaultAdminSlugs.includes('*') && !mgmt.vaultAdminSlugs.includes(slug)) {
      return c.json({ error: `Forbidden: requires vault_admin("${slug}")` }, 403)
    }
    return next()
  }
}

/**
 * Resolves orgId from the token's vaultAdminSlugs and sets it on context.
 * - Wildcard (`*`): uses `?org=` query param, defaults to `'local'`
 * - Single slug: uses that slug
 * Must be used after `requireToken`.
 */
export async function resolveOrgId(c: Context<CoreHonoEnv>, next: Next) {
  const mgmt = c.get('managementRights')
  if (!mgmt) return c.json({ error: 'Forbidden' }, 403)

  const slugs = mgmt.vaultAdminSlugs
  if (slugs.includes('*')) {
    c.set('orgId', c.req.query('org') ?? 'local')
  } else if (slugs.length === 1) {
    const org = c.req.query('org')
    if (org && org !== slugs[0]) return c.json({ error: 'Forbidden for this org' }, 403)
    c.set('orgId', slugs[0])
  } else if (slugs.length > 1) {
    const org = c.req.query('org')
    if (!org) return c.json({ error: 'Multiple orgs available; specify ?org=' }, 400)
    if (!slugs.includes(org)) return c.json({ error: 'Forbidden for this org' }, 403)
    c.set('orgId', org)
  } else {
    return c.json({ error: 'No org access' }, 403)
  }
  return next()
}
