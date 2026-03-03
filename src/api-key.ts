import { Hono } from 'hono'
import type { HonoEnv } from './types'
import { getService, createAuthFlow, getAuthFlow, completeAuthFlow, upsertCredential } from './db/queries'
import { mintToken } from './biscuit'
import { ApiKeyFormPage, SuccessPage, ErrorPage } from './ui'
import { encryptCredentials, buildCredentialHeaders } from './lib/credentials-crypto'

export const apiKeyRoutes = new Hono<HonoEnv>()

function randomId() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

// ─── API Key Form ────────────────────────────────────────────────────────────

apiKeyRoutes.get('/:service/api-key', async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)

  // Create a flow for polling
  const flowId = c.req.query('flow_id') ?? randomId()
  const vaultSlug = c.req.query('vault') ?? 'personal'

  const existingFlow = await getAuthFlow(db, flowId)
  if (!existingFlow) {
    await createAuthFlow(db, {
      id: flowId,
      service: serviceName,
      method: 'api_key',
      vaultSlug,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    })
  }

  return c.html(ApiKeyFormPage({ service: svc, flowId }))
})

// ─── API Key Submit ──────────────────────────────────────────────────────────

apiKeyRoutes.post('/:service/api-key', async c => {
  const serviceName = c.req.param('service')
  const db = c.get('db')
  const svc = await getService(db, serviceName)

  if (!svc) return c.html(ErrorPage({ message: `Unknown service: ${serviceName}` }), 404)

  const formData = await c.req.parseBody()
  const apiKey = formData['api_key'] as string
  const flowId = formData['flow_id'] as string

  if (!apiKey) return c.html(ErrorPage({ message: 'API key is required' }), 400)

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

  // Determine vault from flow or default
  let vaultSlug = 'personal'
  if (flowId) {
    const flow = await getAuthFlow(db, flowId)
    if (flow?.vaultSlug) vaultSlug = flow.vaultSlug
  }

  // Store credential in vault
  const credHeaders = buildCredentialHeaders(svc, apiKey)
  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: credHeaders })
  await upsertCredential(db, vaultSlug, serviceName, encrypted, identity)

  // Mint Warden token with vault binding
  const wardenToken = mintToken(c.env.BISCUIT_PRIVATE_KEY, [
    { services: serviceName, vault: vaultSlug, metadata: { userId: identity } },
  ])

  // Complete the flow if one exists
  if (flowId) {
    const flow = await getAuthFlow(db, flowId)
    if (flow && flow.status !== 'completed') {
      await completeAuthFlow(db, flowId, { wardenToken, identity })
    }
  }

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
