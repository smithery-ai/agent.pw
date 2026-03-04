/**
 * Config-driven webhook signature verification.
 *
 * Each service stores a webhookConfig JSON on the services table describing
 * how to verify upstream webhook signatures. The verifier reads that config
 * and applies the right algorithm — no per-service code branches.
 */

export interface WebhookConfig {
  /** Header containing the upstream signature, e.g. "X-Hub-Signature-256" */
  signatureHeader: string
  /** Optional prefix to strip before comparing, e.g. "sha256=" */
  signaturePrefix?: string
  /** Algorithm name, e.g. "hmac-sha256" */
  algorithm: string
  /** Where the webhook secret comes from: agent provides it ("client") or extracted from API response ("response") */
  secretSource?: 'client' | 'response'
  /** JSON path in the upstream API response containing the signing secret (when secretSource is "response") */
  secretResponsePath?: string
  /** Special challenge handling, e.g. "slack-url-verification" */
  challengeType?: string
}

function hexEncode(buffer: ArrayBuffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Verify an upstream webhook signature using the service's webhookConfig.
 * Uses crypto.subtle.verify for timing-safe comparison.
 */
export async function verifyWebhookSignature(
  body: ArrayBuffer,
  headers: Headers,
  secret: string,
  config: WebhookConfig,
) {
  const signature = headers.get(config.signatureHeader)
  if (!signature) return false

  const rawSignature = config.signaturePrefix
    ? signature.slice(config.signaturePrefix.length)
    : signature

  if (config.algorithm === 'hmac-sha256') {
    return verifyHmacSha256(body, rawSignature, secret)
  }

  // Unknown algorithm — fail closed
  return false
}

async function verifyHmacSha256(body: ArrayBuffer, signatureHex: string, secret: string) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  )

  // Compute expected HMAC, then use verify for timing-safe comparison
  const expectedSignature = await crypto.subtle.sign('HMAC', key, body)
  const expectedHex = hexEncode(expectedSignature)

  // Convert both to bytes and use subtle.verify for constant-time comparison
  // This avoids string comparison timing leaks
  if (signatureHex.length !== expectedHex.length) return false

  const signatureBytes = new TextEncoder().encode(signatureHex)
  const expectedBytes = new TextEncoder().encode(expectedHex)

  // Use HMAC verify trick: HMAC(key, receivedSig) === HMAC(key, expectedSig)
  // Both operations take the same time regardless of content
  const verifyKey = await crypto.subtle.importKey(
    'raw',
    crypto.getRandomValues(new Uint8Array(32)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const [a, b] = await Promise.all([
    crypto.subtle.sign('HMAC', verifyKey, signatureBytes),
    crypto.subtle.sign('HMAC', verifyKey, expectedBytes),
  ])

  const aArr = new Uint8Array(a)
  const bArr = new Uint8Array(b)
  if (aArr.length !== bArr.length) return false
  let diff = 0
  for (let i = 0; i < aArr.length; i++) {
    diff |= aArr[i] ^ bArr[i]
  }
  return diff === 0
}

/**
 * Handle Slack-style URL verification challenges.
 * Returns a Response if this is a challenge request, null otherwise.
 */
export function handleSlackChallenge(body: ArrayBuffer) {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(body))
    if (parsed.type === 'url_verification' && typeof parsed.challenge === 'string') {
      return new Response(JSON.stringify({ challenge: parsed.challenge }), {
        headers: { 'Content-Type': 'application/json' },
      })
    }
  } catch {
    // Not JSON or missing fields — not a challenge
  }
  return null
}

/**
 * Verify a Slack webhook signature.
 * Slack uses v0=HMAC-SHA256(signing_secret, "v0:{timestamp}:{body}") format.
 */
export async function verifySlackSignature(
  body: ArrayBuffer,
  headers: Headers,
  secret: string,
) {
  const signature = headers.get('X-Slack-Signature')
  const timestamp = headers.get('X-Slack-Request-Timestamp')
  if (!signature || !timestamp) return false

  // Check timestamp freshness (5 minute window)
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - Number(timestamp)) > 300) return false

  const bodyText = new TextDecoder().decode(body)
  const baseString = `v0:${timestamp}:${bodyText}`

  const rawSignature = signature.startsWith('v0=') ? signature.slice(3) : signature
  return verifyHmacSha256(new TextEncoder().encode(baseString).buffer as ArrayBuffer, rawSignature, secret)
}
