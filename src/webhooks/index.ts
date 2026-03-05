/**
 * Webhook routes: ingestion (receives upstream webhooks) and registration management.
 *
 * Ingestion endpoints are unauthenticated — upstream services POST directly.
 * Management endpoints require a Warden token.
 */

import { Hono } from 'hono'
import type { CoreHonoEnv } from '../core/types'
import { requireToken } from '../core/middleware'
import { extractVaultFromToken, getPublicKeyHex, extractFirstVault } from '../biscuit'
import {
  getWebhookRegistration,
  listWebhookRegistrations,
  upsertWebhookRegistration,
  deleteWebhookRegistration,
  getService,
} from '../db/queries'
import { encryptCredentials, decryptCredentials } from '../lib/credentials-crypto'
import { verifyWebhookSignature, verifySlackSignature, handleSlackChallenge, type WebhookConfig } from './verify'
import {
  signEnvelope,
  buildJwks,
  extractRelevantHeaders,
  randomId,
  tryParseJson,
  type WardenWebhookEnvelope,
} from './envelope'

export function webhookRoutes() {
  const hooks = new Hono<CoreHonoEnv>()

  // ─── JWKS endpoint ────────────────────────────────────────────────────────

  hooks.get('/.well-known/jwks.json', c => {
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    return c.json(buildJwks(publicKeyHex))
  })

  // ─── Registration Management ──────────────────────────────────────────────

  hooks.get('/hooks/registrations', requireToken, async c => {
    const db = c.get('db')
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const token = c.get('token')!

    const orgId = extractFirstVault(token, publicKeyHex)
    if (!orgId) {
      return c.json({ error: 'No org scope found in token' }, 403)
    }

    const registrations = await listWebhookRegistrations(db, orgId)
    return c.json(
      registrations.map(r => ({
        id: r.id,
        service: r.service,
        callbackUrl: r.callbackUrl,
        hookUrl: `${c.env.BASE_URL}/hooks/${r.service}/${r.id}`,
        createdAt: r.createdAt,
      })),
    )
  })

  hooks.post('/hooks/registrations', requireToken, async c => {
    const db = c.get('db')
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const token = c.get('token')!

    const body = await c.req.json<{
      service: string
      callbackUrl: string
      webhookSecret?: string
      metadata?: Record<string, string>
    }>()

    if (!body.service || !body.callbackUrl) {
      return c.json({ error: 'service and callbackUrl are required' }, 400)
    }

    const orgId = extractVaultFromToken(token, publicKeyHex, body.service)
    if (!orgId) {
      return c.json({ error: `No org scope found in token for ${body.service}` }, 403)
    }

    const id = randomId()
    const encryptedSecret = body.webhookSecret
      ? await encryptCredentials(c.env.ENCRYPTION_KEY, { headers: { secret: body.webhookSecret } })
      : null

    await upsertWebhookRegistration(db, id, {
      orgId,
      service: body.service,
      callbackUrl: body.callbackUrl,
      encryptedWebhookSecret: encryptedSecret,
      metadata: body.metadata ? JSON.stringify(body.metadata) : undefined,
    })

    return c.json({
      id,
      hookUrl: `${c.env.BASE_URL}/hooks/${body.service}/${id}`,
    }, 201)
  })

  hooks.delete('/hooks/registrations/:id', requireToken, async c => {
    const db = c.get('db')
    const publicKeyHex = getPublicKeyHex(c.env.BISCUIT_PRIVATE_KEY)
    const token = c.get('token')!
    const id = c.req.param('id')

    const orgId = extractFirstVault(token, publicKeyHex)
    if (!orgId) {
      return c.json({ error: 'No org scope found in token' }, 403)
    }

    const deleted = await deleteWebhookRegistration(db, id, orgId)
    if (!deleted) return c.json({ error: 'Registration not found' }, 404)
    return c.json({ ok: true })
  })

  // ─── Webhook Ingestion ────────────────────────────────────────────────────

  hooks.all('/hooks/:hostname/*', async c => {
    const hostname = c.req.param('hostname')
    const url = new URL(c.req.url)
    const hookPath = url.pathname.slice(`/hooks/${hostname}/`.length)

    if (!hookPath) {
      return c.json({ error: 'Missing hook path' }, 400)
    }

    const db = c.get('db')
    const registration = await getWebhookRegistration(db, hostname, hookPath)
    if (!registration) {
      return c.json({ error: 'Unknown webhook endpoint' }, 404)
    }

    const body = await c.req.raw.arrayBuffer()

    // Load service webhook config
    const svc = await getService(db, hostname)
    const webhookConfig: WebhookConfig | null = svc?.webhookConfig
      ? JSON.parse(svc.webhookConfig)
      : null

    // Handle Slack URL verification challenge
    if (webhookConfig?.challengeType === 'slack-url-verification') {
      const challengeResponse = handleSlackChallenge(body)
      if (challengeResponse) return challengeResponse
    }

    // Verify upstream signature
    if (registration.encryptedWebhookSecret && webhookConfig) {
      const stored = await decryptCredentials(c.env.ENCRYPTION_KEY, registration.encryptedWebhookSecret)
      const secret = stored.headers.secret

      let valid: boolean
      if (webhookConfig.challengeType === 'slack-url-verification') {
        valid = await verifySlackSignature(body, c.req.raw.headers, secret)
      } else {
        valid = await verifyWebhookSignature(body, c.req.raw.headers, secret, webhookConfig)
      }

      if (!valid) {
        return c.json({ error: 'Invalid upstream signature' }, 401)
      }
    }

    // Build envelope
    const envelope: WardenWebhookEnvelope = {
      warden_version: '1',
      event_id: randomId(),
      service: hostname,
      received_at: new Date().toISOString(),
      hook_path: hookPath,
      upstream_headers: extractRelevantHeaders(c.req.raw.headers),
      payload: tryParseJson(body),
    }

    const envelopeJson = JSON.stringify(envelope)

    // Sign with Ed25519
    const signature = await signEnvelope(envelopeJson, c.env.BISCUIT_PRIVATE_KEY)

    // Forward to callback (fire-and-forget)
    const forwardPromise = fetch(registration.callbackUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Warden-Signature': signature,
        'Warden-Event-Id': envelope.event_id,
      },
      body: envelopeJson,
    }).catch(err => {
      console.error(`[hooks] forward failed for ${hostname}/${hookPath}:`, err.message)
    })

    // Use waitUntil if available (Cloudflare Workers), otherwise let the promise run
    try {
      if (c.executionCtx?.waitUntil) {
        c.executionCtx.waitUntil(forwardPromise)
      }
    } catch {
      // executionCtx throws in Node.js — the promise runs detached
    }

    // Return 200 to upstream immediately
    return c.json({ ok: true })
  })

  return hooks
}
