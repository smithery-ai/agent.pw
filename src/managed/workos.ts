import { Hono } from 'hono'
import { WorkOS } from '@workos-inc/node'
import type { HonoEnv } from './types'
import { buildSetCookieHeader, SESSION_TTL_SECONDS } from './session'
import { getUser, upsertUser } from '../db/queries'

export const workosRoutes = new Hono<HonoEnv>()

function getWorkOS(apiKey: string) {
  return new WorkOS(apiKey)
}

// ─── Login ──────────────────────────────────────────────────────────────────

workosRoutes.get('/login', async c => {
  const returnTo = c.req.query('return_to') ?? '/'
  const state = btoa(JSON.stringify({ return_to: returnTo }))
  const workos = getWorkOS(c.env.WORKOS_API_KEY!)

  const url = workos.userManagement.getAuthorizationUrl({
    provider: 'authkit',
    redirectUri: `${c.env.BASE_URL}/auth/callback`,
    clientId: c.env.WORKOS_CLIENT_ID!,
    state,
  })

  return c.redirect(url)
})

// ─── Callback ───────────────────────────────────────────────────────────────

workosRoutes.get('/callback', async c => {
  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')

  if (error) return c.json({ error: `WorkOS error: ${error}` }, 400)
  if (!code) return c.json({ error: 'Missing code parameter' }, 400)

  const workos = getWorkOS(c.env.WORKOS_API_KEY!)

  const { user } = await workos.userManagement.authenticateWithCode({
    clientId: c.env.WORKOS_CLIENT_ID!,
    code,
  })

  const name = [user.firstName, user.lastName].filter(Boolean).join(' ') || undefined
  const db = c.get('db')

  // Check if user already exists (has an org)
  let existing = await getUser(db, user.id)

  if (!existing) {
    // Create a personal org for the user
    const org = await workos.organizations.createOrganization({
      name: `${user.email}'s workspace`,
    })

    await workos.userManagement.createOrganizationMembership({
      userId: user.id,
      organizationId: org.id,
    })

    await upsertUser(db, {
      workosUserId: user.id,
      workosOrgId: org.id,
      email: user.email,
      name,
    })

    existing = { workosUserId: user.id, workosOrgId: org.id, email: user.email, name: name ?? null, createdAt: new Date() }
  }

  // Build session and set cookie
  const session = {
    workosUserId: user.id,
    orgId: existing.workosOrgId,
    email: user.email,
    name,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  }

  const cookie = await buildSetCookieHeader(c.env.WORKOS_COOKIE_PASSWORD!, session)

  // Redirect to return_to
  let returnTo = '/'
  if (state) {
    try {
      returnTo = JSON.parse(atob(state)).return_to ?? '/'
    } catch {
      // ignore malformed state
    }
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: returnTo,
      'Set-Cookie': cookie,
    },
  })
})
