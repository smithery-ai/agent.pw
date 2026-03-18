import type { Hono } from 'hono'

export interface BrowserSessionTokenResponse {
  token: string
  expiresAt: string
  user: {
    id: string
    email: string
    name: string | null
  }
  orgId: string
}

export interface BrowserSessionTokenChallenge {
  error: string
  loginUrl?: string
}

export function mountBrowserAuthRoutes(
  app: Hono<any>,
  routes: Hono<any> | null | undefined,
) {
  if (!routes) return
  app.route('/auth', routes)
}
