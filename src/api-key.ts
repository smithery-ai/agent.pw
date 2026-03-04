import { Hono } from 'hono'
import type { HonoEnv } from './types'
import { getService, upsertCredential } from './db/queries'
import { createAuthFlow, getAuthFlow, completeAuthFlow } from './lib/auth-flow-store'
import { mintToken } from './biscuit'
import { requireBrowserSession } from './middleware'
import { ApiKeyFormPage, SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders } from './lib/credentials-crypto'

export const apiKeyRoutes = new Hono<HonoEnv>()

function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

// ─── API Key Form ────────────────────────────────────────────────────────────

apiKeyRoutes.get('/:service/api-key', requireBrowserSession, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)

  const session = c.get('session')!
  const orgId = session.orgId

  // Create a flow for SSE/polling
  const flowId = c.req.query('flow_id') ?? randomId()

  const redis = c.get('redis')
  const existingFlow = await getAuthFlow(redis, flowId)
  if (!existingFlow) {
    await createAuthFlow(redis, {
      id: flowId,
      service: serviceName,
      method: 'api_key',
      orgId,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    })
  }

  return c.html(ApiKeyFormPage({ service: svc, flowId }))
})

// ─── API Key Submit ──────────────────────────────────────────────────────────

apiKeyRoutes.post('/:service/api-key', requireBrowserSession, async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)
  const isJson = c.req.header('Content-Type')?.includes('application/json')

  if (!svc) {
    if (isJson) return c.json({ error: `Unknown service: ${serviceName}` }, 404)
    return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)
  }

  // Parse input based on content type
  let apiKey: string
  let flowId: string | undefined
  if (isJson) {
    const body = await c.req.json<{ api_key?: string; flow_id?: string }>()
    apiKey = body.api_key ?? ''
    flowId = body.flow_id ?? c.req.query('flow_id')
  } else {
    const formData = await c.req.parseBody()
    apiKey = formData.api_key as string
    flowId = formData.flow_id as string
  }

  if (!apiKey) {
    if (isJson) return c.json({ error: 'api_key is required' }, 400)
    return c.html(ErrorPage({ message: 'API key is required' }), 400)
  }

  // Optionally validate the key via a "whoami" call
  const authConfig: Record<string, string> = svc.authConfig ? JSON.parse(svc.authConfig) : {}
  let identity = 'default'

  if (authConfig.identity_url) {
    try {
      const headers: Record<string, string> = {}

      // Use the service's auth method to build the validation request
      if (svc.authMethod === 'bearer' || svc.authMethod === 'oauth2') {
        headers[svc.headerName] = `${svc.headerScheme} ${apiKey}`
      } else if (svc.authMethod === 'api_key') {
        headers[svc.headerName] = apiKey
      } else if (svc.authMethod === 'basic') {
        headers[svc.headerName] = `Basic ${btoa(apiKey)}`
      }

      let identityRes: Response

      if (authConfig.identity_method === 'POST') {
        headers['Content-Type'] = 'application/json'
        identityRes = await fetch(authConfig.identity_url, {
          method: 'POST',
          headers,
          body: authConfig.identity_body || undefined,
        })
      } else {
        identityRes = await fetch(authConfig.identity_url, { headers })
      }

      if (!identityRes.ok) {
        if (isJson) return c.json({ error: 'Invalid API key. The upstream service rejected it.' }, 400)
        return c.html(
          ErrorPage({ message: 'Invalid API key. The upstream service rejected it.' }),
          400,
        )
      }

      const data = (await identityRes.json()) as Record<string, unknown>
      if (authConfig.identity_path) {
        const resolved = getNestedValue(data, authConfig.identity_path)
        if (typeof resolved === 'string') {
          identity = resolved
        }
      }
    } catch {
      // Validation failed but don't block — store with default identity
    }
  }

  const session = c.get('session')!
  const orgId = session.orgId

  // Store credential in org
  const credHeaders = buildCredentialHeaders(svc, apiKey)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })
  await upsertCredential(db, orgId, serviceName, 'default', encrypted)

  // Mint master biscuit — covers all services in user's org
  const wardenToken = mintToken(c.env.BISCUIT_PRIVATE_KEY, [
    { vault: orgId, metadata: { userId: session.workosUserId } },
  ])

  // Complete the flow if one exists
  if (flowId) {
    const redis = c.get('redis')
    const flow = await getAuthFlow(redis, flowId)
    if (flow && flow.status !== 'completed') {
      await completeAuthFlow(redis, flowId, { wardenToken, identity, orgId })
    }
  }

  if (isJson) return c.json({ token: wardenToken, identity })
  return c.html(SuccessPage({ token: wardenToken, service: svc }))
})

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.')
  let current: unknown = obj
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}
