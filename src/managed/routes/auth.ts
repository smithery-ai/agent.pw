import { Hono } from 'hono'
import { streamSSE } from 'hono/streaming'
import type { HonoEnv } from '../types'
import { requireBrowserSession } from '../middleware'
import { getService, createAuthFlow, getAuthFlow } from '../../db/queries'
import { AuthPage, ErrorPage } from '../ui'
import { oauthRoutes } from '../oauth'
import { apiKeyRoutes } from '../api-key'
import { workosRoutes } from '../workos'
import { randomId, validateFlowId } from '../../lib/utils'

export const authRoutes = new Hono<HonoEnv>()

// WorkOS login/callback — only available when WorkOS is configured
authRoutes.use('/login', async (c, next) => {
  if (!c.env.WORKOS_CLIENT_ID) return c.json({ error: 'WorkOS not configured' }, 404)
  return next()
})
authRoutes.use('/callback', async (c, next) => {
  if (!c.env.WORKOS_CLIENT_ID) return c.json({ error: 'WorkOS not configured' }, 404)
  return next()
})
authRoutes.route('/', workosRoutes)

// Tabbed auth page — requires browser session
authRoutes.get('/:service', requireBrowserSession, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) {
    return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)
  }

  const flowId = validateFlowId(c.req.query('flow_id')) ?? randomId()

  // Ensure a flow exists for polling
  const existingFlow = await getAuthFlow(c.get('db'), flowId)
  if (!existingFlow) {
    await createAuthFlow(c.get('db'), {
      id: flowId,
      service: serviceName,
      method: 'api_key',
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    })
  }

  const callbackUrl = `${new URL(c.req.url).origin}/auth/${serviceName}/oauth/callback`
  return c.html(AuthPage({ service: svc, flowId, callbackUrl }))
})

// OAuth and API key flows
authRoutes.route('/', oauthRoutes)
authRoutes.route('/', apiKeyRoutes)

// Auth flow status polling
authRoutes.get('/status/:flowId', async c => {
  const db = c.get('db')
  const flowId = c.req.param('flowId')
  const accept = c.req.header('Accept')

  // SSE mode — hold connection until flow completes
  if (accept?.includes('text/event-stream')) {
    return streamSSE(c, async (stream) => {
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const flow = await getAuthFlow(db, flowId)
        if (!flow) {
          await stream.writeSSE({ event: 'error', data: JSON.stringify({ error: 'Flow not found or expired' }) })
          return
        }
        if (flow.status === 'completed') {
          await stream.writeSSE({
            event: 'complete',
            data: JSON.stringify({ status: 'completed', token: flow.token, identity: flow.identity }),
          })
          return
        }
        await stream.writeSSE({ event: 'pending', data: JSON.stringify({ status: 'pending' }) })
        await new Promise(r => setTimeout(r, 2000))
      }
    })
  }

  // Fallback: JSON polling (backward compat)
  const flow = await getAuthFlow(db, flowId)
  if (!flow) return c.json({ error: 'Flow not found' }, 404)

  if (flow.status === 'completed') {
    return c.json({ status: 'completed', token: flow.token, identity: flow.identity })
  }

  return c.json({ status: 'pending' }, 202)
})
