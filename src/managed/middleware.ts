import type { Context, Next } from 'hono'
import type { HonoEnv } from './types'
import { getSessionFromCookie } from './session'

export async function requireBrowserSession(c: Context<HonoEnv>, next: Next) {
  if (!c.env.WORKOS_COOKIE_PASSWORD) {
    // No session auth configured — allow through (self-hosted mode)
    return next()
  }

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
  if (c.env.WORKOS_COOKIE_PASSWORD) {
    const session = await getSessionFromCookie(c.req.header('Cookie'), c.env.WORKOS_COOKIE_PASSWORD)
    if (session) {
      c.set('session', session)
    }
  }
  return next()
}
