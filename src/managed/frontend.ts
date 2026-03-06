import type { Context } from 'hono'
import type { HonoEnv } from './types'

/** Resolves the frontend URL for redirects to the Next.js app. */
export function frontendUrl(c: Context<HonoEnv>) {
  return c.env.FRONTEND_URL ?? c.env.BASE_URL
}

/** Redirect to the frontend success page. */
export function redirectToSuccess(c: Context<HonoEnv>, token: string, service: string) {
  const base = frontendUrl(c)
  return c.redirect(
    `${base}/success?token=${encodeURIComponent(token)}&service=${encodeURIComponent(service)}`,
  )
}

/** Redirect to the frontend error page. */
export function redirectToError(c: Context<HonoEnv>, message: string, status?: number) {
  const base = frontendUrl(c)
  return c.redirect(
    `${base}/error?message=${encodeURIComponent(message)}`,
    status === 400 ? 302 : 302,
  )
}
