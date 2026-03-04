import type { Context } from 'hono'
import type { HonoEnv } from './types'
import {
  authorizeRequest,
  extractVaultFromToken,
  getPublicKeyHex,
  getRevocationIds,
} from './biscuit'
import { getCredential, getService, isRevoked, upsertCredential, upsertWebhookRegistration } from './db/queries'
import {
  decryptCredentials,
  encryptCredentials,
  buildCredentialHeaders,
  type StoredCredentials,
} from './lib/credentials-crypto'
import { refreshOAuthToken } from './oauth'
import { randomId } from './webhooks/envelope'
import type { WebhookConfig } from './webhooks/verify'

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  try {
    return JSON.stringify(e)
  } catch /* v8 ignore start */ {
    return String(e)
  } /* v8 ignore stop */
}

/** Traverse a nested object by dot-separated path, e.g. "data.secret" */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  let current: unknown = obj
  for (const key of path.split('.')) {
    if (current == null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[key]
  }
  return current
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null
  return header.startsWith('Bearer ') ? header.slice(7) : header
}

function shouldRefresh(expiresAt: string | undefined): boolean {
  if (!expiresAt) return false
  const expiresMs = new Date(expiresAt).getTime()
  if (Number.isNaN(expiresMs)) return false
  return expiresMs - Date.now() <= 5 * 60 * 1000
}

async function refreshCredentialIfNeeded(
  c: Context<HonoEnv>,
  service: Awaited<ReturnType<typeof getService>>,
  orgId: string,
  cred: Awaited<ReturnType<typeof getCredential>>,
  stored: StoredCredentials,
): Promise<StoredCredentials> {
  if (!service || !cred || !stored.oauth?.refreshToken) {
    return stored
  }
  if (!shouldRefresh(stored.oauth.expiresAt)) {
    return stored
  }

  const authConfig: Record<string, string> = service.authConfig
    ? JSON.parse(service.authConfig)
    : {}

  const refreshed = await refreshOAuthToken({
    tokenUrl: stored.oauth.tokenUrl,
    refreshToken: stored.oauth.refreshToken,
    clientId: stored.oauth.clientId,
    clientSecret: stored.oauth.clientSecret,
    scopes: stored.oauth.scopes,
    authConfig,
  })

  const nextStored: StoredCredentials = {
    ...stored,
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, refreshed.accessToken),
    oauth: {
      ...stored.oauth,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      expiresAt: refreshed.expiresAt,
    },
  }

  const encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, nextStored)
  await upsertCredential(c.get('db'), orgId, service.service, 'default', encrypted)

  return nextStored
}

export async function handleProxy(
  c: Context<HonoEnv>,
  service: string,
  upstreamPath: string,
) {
  const token = extractBearerToken(c.req.header('Authorization'))
  if (!token) return c.json({ error: 'Missing Authorization header' }, 401)

  const db = c.get('db')
  const svc = await getService(db, service)
  if (!svc) return c.json({ error: `Unknown service: ${service}` }, 404)

  const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)

  // Check revocation
  try {
    const revIds = getRevocationIds(token, publicKeyHex)
    for (const id of revIds) {
      if (await isRevoked(db, id)) {
        return c.json({ error: 'Token has been revoked' }, 403)
      }
    }
  } catch (e) {
    return c.json({ error: `Invalid token: ${errorMessage(e)}` }, 401)
  }

  // Authorize
  const result = authorizeRequest(token, publicKeyHex, service, c.req.method, upstreamPath)
  if (!result.authorized) {
    return c.json({ error: 'Forbidden', details: result.error }, 403)
  }

  // Extract org from token (grant_vault carries org_id)
  const orgId = extractVaultFromToken(token, publicKeyHex, service)
  if (!orgId) {
    return c.json({ error: `No org scope found in token for ${service}` }, 403)
  }

  // Look up credential by (org_id, service, slug)
  const cred = await getCredential(db, orgId, service)
  if (!cred) {
    return c.json({ error: `No credential found for ${service} in org "${orgId}"` }, 404)
  }

  // Build upstream request
  const url = new URL(c.req.url)
  const upstreamUrl = `${svc.baseUrl.replace(/\/$/, '')}${upstreamPath}${url.search}`

  const headers = new Headers()
  c.req.raw.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'authorization') return
    if (key.toLowerCase() === 'host') return
    headers.set(key, value)
  })

  // Inject credential headers
  let stored = await decryptCredentials(c.env.ENCRYPTION_KEY, cred.encryptedCredentials)
  try {
    stored = await refreshCredentialIfNeeded(c, svc, orgId, cred, stored)
  } catch (e) {
    return c.json({ error: `OAuth token refresh failed: ${errorMessage(e)}` }, 401)
  }
  for (const [name, value] of Object.entries(stored.headers)) {
    headers.set(name, value)
  }

  // ─── Webhook registration interception ─────────────────────────────────
  // When Warden-Callback is present, this is a webhook creation request.
  // Generate hookUrl + secret, replace placeholders, and register the forwarding target.

  const wardenCallback = c.req.header('Warden-Callback')
  let webhookRegistrationId: string | undefined
  headers.delete('warden-callback')

  // Forward request
  let body: ArrayBuffer | string | undefined
  if (['GET', 'HEAD'].includes(c.req.method)) {
    body = undefined
  } else {
    body = await c.req.raw.arrayBuffer()
  }

  if (wardenCallback && body) {
    const registrationId = randomId()
    const webhookSecret = randomId() + randomId() // 64-char hex secret
    const hookUrl = `${c.env.BASE_URL}/hooks/${service}/${registrationId}`

    let bodyText = new TextDecoder().decode(body)
    bodyText = bodyText.replace(/\$WARDEN_HOOK_URL/g, hookUrl)
    bodyText = bodyText.replace(/\$WARDEN_HOOK_SECRET/g, webhookSecret)
    body = bodyText

    // Encrypt and store the webhook secret
    const encryptedSecret = await encryptCredentials(c.env.ENCRYPTION_KEY, {
      headers: { secret: webhookSecret },
    })

    await upsertWebhookRegistration(db, registrationId, {
      orgId,
      service,
      callbackUrl: wardenCallback,
      encryptedWebhookSecret: encryptedSecret,
    })

    webhookRegistrationId = registrationId
  }

  const log = c.get('logger')
  log.info({
    service,
    orgId,
    method: c.req.method,
    upstreamUrl,
    requestHeaders: Object.fromEntries(headers.entries()),
  }, 'proxy request')

  const upstream = await fetch(upstreamUrl, {
    method: c.req.method,
    headers,
    body,
  })

  log.info({
    service,
    orgId,
    method: c.req.method,
    upstreamUrl,
    status: upstream.status,
    responseHeaders: Object.fromEntries(upstream.headers.entries()),
  }, 'proxy response')

  // For services with secretSource "response", extract and store the webhook secret
  if (wardenCallback && webhookRegistrationId && upstream.ok) {
    const webhookConfig: WebhookConfig | null = svc.webhookConfig
      ? JSON.parse(svc.webhookConfig)
      : null

    if (webhookConfig?.secretSource === 'response' && webhookConfig.secretResponsePath) {
      try {
        const responseBody = await upstream.clone().json() as Record<string, unknown>
        const secret = getNestedValue(responseBody, webhookConfig.secretResponsePath)
        if (typeof secret === 'string') {
          const encryptedSecret = await encryptCredentials(c.env.ENCRYPTION_KEY, {
            headers: { secret },
          })
          await upsertWebhookRegistration(db, webhookRegistrationId, {
            orgId,
            service,
            callbackUrl: wardenCallback,
            encryptedWebhookSecret: encryptedSecret,
          })
        }
      } catch {
        // Response parsing failed — the client-provided secret (if any) remains
      }
    }
  }

  // Return response transparently
  const responseHeaders = new Headers(upstream.headers)
  responseHeaders.delete('transfer-encoding')

  if (webhookRegistrationId) {
    responseHeaders.set('Warden-Registration-Id', webhookRegistrationId)
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  })
}
