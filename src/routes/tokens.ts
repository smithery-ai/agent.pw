import { Hono } from 'hono'
import type { CoreHonoEnv, ProxyConstraint } from '../core/types'
import { requireToken, requireRight } from '../core/middleware'
import {
  mintToken,
  mintManagementToken,
  restrictToken,
  getPublicKeyHex,
  getRevocationIds,
  generateKeyPairHex,
} from '../biscuit'
import { revokeToken } from '../db/queries'
import { errorMessage } from '../lib/utils'

export const tokenRoutes = new Hono<CoreHonoEnv>()

tokenRoutes.post('/mint', requireToken, async c => {
  const body = await c.req.json<{
    grants?: ProxyConstraint[]
    bindings?: Record<string, { vault: string }>
    rights?: string[]
    vaultAdmin?: string[]
  }>()

  const mgmt = c.get('managementRights')!

  // Mint management tokens
  if (body.rights || body.vaultAdmin) {
    if (!mgmt.rights.includes('manage_vaults') && !mgmt.vaultAdminSlugs.includes('*')) {
      return c.json({ error: 'Forbidden: requires "manage_vaults" right' }, 403)
    }
    try {
      const token = mintManagementToken(
        c.env.BISCUIT_PRIVATE_KEY,
        body.rights ?? [],
        body.vaultAdmin ?? [],
      )
      const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      return c.json({ token, publicKey })
    } catch (e) /* v8 ignore start */ {
      return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
    } /* v8 ignore stop */
  }

  // Mint proxy tokens with bindings format
  if (body.bindings && Object.keys(body.bindings).length > 0) {
    for (const [, binding] of Object.entries(body.bindings)) {
      const allowed =
        mgmt.vaultAdminSlugs.includes('*') || mgmt.vaultAdminSlugs.includes(binding.vault)
      if (!allowed) {
        return c.json(
          { error: `Forbidden: no vault_admin for "${binding.vault}"` },
          403,
        )
      }
    }

    const grants: ProxyConstraint[] = Object.entries(body.bindings).map(
      ([service, binding]) => ({
        services: service,
        vault: binding.vault,
      }),
    )

    try {
      const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, grants)
      const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      return c.json({ token, publicKey })
    } catch (e) /* v8 ignore start */ {
      return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
    } /* v8 ignore stop */
  }

  // Mint proxy tokens with grants format
  if (body.grants && body.grants.length > 0) {
    for (const grant of body.grants) {
      if (grant.vault) {
        const allowed =
          mgmt.vaultAdminSlugs.includes('*') || mgmt.vaultAdminSlugs.includes(grant.vault)
        if (!allowed) {
          return c.json(
            { error: `Forbidden: no vault_admin for "${grant.vault}"` },
            403,
          )
        }
      }
    }

    try {
      const token = mintToken(c.env.BISCUIT_PRIVATE_KEY, body.grants)
      const publicKey = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
      return c.json({ token, publicKey })
    } catch (e) /* v8 ignore start */ {
      return c.json({ error: `Failed to mint token: ${errorMessage(e)}` }, 500)
    } /* v8 ignore stop */
  }

  return c.json(
    { error: 'One of grants, bindings, rights, or vaultAdmin is required' },
    400,
  )
})

tokenRoutes.post('/restrict', async c => {
  const body = await c.req.json<{ token: string; constraints: ProxyConstraint[] }>()
  if (!body.token) return c.json({ error: 'token is required' }, 400)
  if (!body.constraints || body.constraints.length === 0) {
    return c.json({ error: 'constraints array is required' }, 400)
  }

  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
  try {
    const restricted = restrictToken(body.token, publicKeyHex, body.constraints)
    return c.json({ token: restricted })
  } catch (e) {
    return c.json({ error: `Failed to restrict token: ${errorMessage(e)}` }, 400)
  }
})

tokenRoutes.post('/revoke', requireToken, async c => {
  const body = await c.req.json<{ token: string; reason?: string }>()
  if (!body.token) return c.json({ error: 'token is required' }, 400)

  try {
    const db = c.get('db')
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(body.token, publicKeyHex)
    for (const id of revIds) {
      await revokeToken(db, id, body.reason)
    }
    return c.json({ ok: true, revokedIds: revIds })
  } catch (e) {
    return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
  }
})

export const keyRoutes = new Hono<CoreHonoEnv>()

keyRoutes.post('/generate', requireToken, requireRight('manage_services'), async c => {
  return c.json(generateKeyPairHex())
})
