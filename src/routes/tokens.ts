import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import { getPublicKeyHex, getRevocationIds } from '../biscuit'
import { revokeToken } from '../db/queries'
import { errorMessage } from '../lib/utils'

export const tokenRoutes = new Hono<CoreHonoEnv>()

tokenRoutes.post('/revoke', requireToken, async c => {
  const body = await c.req.json<{ reason?: string }>().catch(() => ({}) as { reason?: string })

  try {
    const db = c.get('db')
    const token = c.get('token')!
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const revIds = getRevocationIds(token, publicKeyHex)
    for (const id of revIds) {
      await revokeToken(db, id, body.reason)
    }
    return c.json({ ok: true, revokedIds: revIds })
  } catch (e) {
    return c.json({ error: `Failed to revoke token: ${errorMessage(e)}` }, 400)
  }
})
