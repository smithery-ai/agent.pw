import type { Context, Next } from 'hono'
import type { HonoEnv } from './types'
import { extractBearerToken } from './proxy'
import {
  extractManagementRights,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import { isRevoked } from './db/queries'
import { getSessionFromCookie } from './lib/session'

export async function requireToken(c: Context<HonoEnv>, next: Next) {
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
  return async (c: Context<HonoEnv>, next: Next) => {
    const mgmt = c.get('managementRights')
    if (!mgmt || !mgmt.rights.includes(right)) {
      return c.json({ error: `Forbidden: requires "${right}" right` }, 403)
    }
    return next()
  }
}

export function requireVaultAdmin(paramName: string) {
  return async (c: Context<HonoEnv>, next: Next) => {
    const slug = c.req.param(paramName)
    const mgmt = c.get('managementRights')
    if (!mgmt) return c.json({ error: 'Forbidden' }, 403)
    if (!mgmt.vaultAdminSlugs.includes('*') && !mgmt.vaultAdminSlugs.includes(slug)) {
      return c.json({ error: `Forbidden: requires vault_admin("${slug}")` }, 403)
    }
    return next()
  }
}

export async function requireBrowserSession(c: Context<HonoEnv>, next: Next) {
  const session = await getSessionFromCookie(c.req.header('Cookie'), c.env.WORKOS_COOKIE_PASSWORD)

  if (!session) {
    const url = new URL(c.req.url)
    const returnTo = url.pathname + url.search
    return c.redirect(`/auth/login?return_to=${encodeURIComponent(returnTo)}`)
  }

  c.set('session', session)
  return next()
}

export async function optionalSession(c: Context<HonoEnv>, next: Next) {
  const session = await getSessionFromCookie(c.req.header('Cookie'), c.env.WORKOS_COOKIE_PASSWORD)
  if (session) {
    c.set('session', session)
  }
  return next()
}
