import { Hono } from 'hono'
import type { HonoEnv } from './types'
import { getService, upsertCredential, createAuthFlow, getAuthFlow, completeAuthFlow } from '../db/queries'
import { mintManagementToken } from '../biscuit'
import { requireBrowserSession } from './middleware'
import { ApiKeyFormPage, SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders } from '../lib/credentials-crypto'
import { parseAuthSchemes, getApiKeyScheme, DEFAULT_API_KEY_SCHEME } from '../auth-schemes'

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

  const session = c.get('session')
  const orgId = session?.orgId ?? 'local'

  // Create a flow for SSE/polling
  const flowId = c.req.query('flow_id') ?? randomId()

  const existingFlow = await getAuthFlow(db, flowId)
  if (!existingFlow) {
    await createAuthFlow(db, {
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

  // Validate the key via a "whoami" call (or fallback to base URL probe)
  const authConfig: Record<string, string> = svc.authConfig ? JSON.parse(svc.authConfig) : {}
  const apiKeyScheme = getApiKeyScheme(parseAuthSchemes(svc.authSchemes)) ?? DEFAULT_API_KEY_SCHEME
  let identity = 'default'

  const validationUrl = authConfig.identity_url ?? svc.baseUrl
  try {
    const headers: Record<string, string> = buildCredentialHeaders(apiKeyScheme, apiKey)

    let identityRes: Response

    if (authConfig.identity_url && authConfig.identity_method === 'POST') {
      headers['Content-Type'] = 'application/json'
      identityRes = await fetch(authConfig.identity_url, {
        method: 'POST',
        headers,
        body: authConfig.identity_body || undefined,
      })
    } else {
      identityRes = await fetch(validationUrl, { headers })
    }

    if (identityRes.status === 401) {
      const msg = 'Invalid API key. The upstream service rejected it.'
      if (isJson) return c.json({ error: msg, hint: `${validationUrl} returned 401 Unauthorized.` }, 400)
      return c.html(ErrorPage({ message: msg }), 400)
    }

    if (authConfig.identity_url && identityRes.ok) {
      const data = (await identityRes.json()) as Record<string, unknown>
      if (authConfig.identity_path) {
        const resolved = getNestedValue(data, authConfig.identity_path)
        if (typeof resolved === 'string') {
          identity = resolved
        }
      }
    }
  } catch {
    // Validation failed (network error, etc.) — don't block, store with default identity
  }

  const session = c.get('session')
  const orgId = session?.orgId ?? 'local'

  // Store credential in org
  const credHeaders = buildCredentialHeaders(apiKeyScheme, apiKey)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })
  await upsertCredential(db, orgId, serviceName, 'default', encrypted)

  // Mint token with vault_admin + proxy grants so the user can both manage credentials and proxy
  const token = mintManagementToken(c.env.BISCUIT_PRIVATE_KEY, [], [orgId], [
    { vault: orgId, metadata: { userId: session?.workosUserId ?? identity } },
  ])

  // Complete the flow if one exists
  if (flowId) {
    const flow = await getAuthFlow(db, flowId)
    if (flow && flow.status !== 'completed') {
      await completeAuthFlow(db, flowId, { token, identity, orgId })
    }
  }

  if (isJson) return c.json({ token, identity })
  return c.html(SuccessPage({ token, service: svc }))
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
