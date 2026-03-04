/**
 * Warden webhook envelope and Ed25519 signing.
 *
 * Every forwarded webhook is wrapped in a consistent envelope and signed
 * with Warden's Ed25519 private key. Clients verify using the public key
 * published at /.well-known/jwks.json — no per-registration secrets needed.
 */

export interface WardenWebhookEnvelope {
  warden_version: '1'
  event_id: string
  service: string
  received_at: string
  hook_path: string
  upstream_headers: Record<string, string>
  payload: unknown
}

function hexToBytes(hex: string) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function base64urlEncode(bytes: Uint8Array) {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Ed25519 PKCS8 prefix: wraps a 32-byte raw key into DER-encoded PKCS8
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
])

/**
 * Sign an envelope JSON string with Ed25519.
 * Returns the signature as hex.
 */
export async function signEnvelope(envelopeJson: string, privateKeyHex: string) {
  // Strip the ed25519-private/ prefix if present (Biscuit format)
  const rawHex = privateKeyHex.replace(/^ed25519-private\//, '')
  const keyBytes = hexToBytes(rawHex)

  // Wrap raw 32-byte key in PKCS8 format (required by Node.js crypto.subtle)
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + keyBytes.length)
  pkcs8.set(ED25519_PKCS8_PREFIX)
  pkcs8.set(keyBytes, ED25519_PKCS8_PREFIX.length)

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    false,
    ['sign'],
  )

  const data = new TextEncoder().encode(envelopeJson)
  const signature = await crypto.subtle.sign('Ed25519', cryptoKey, data)
  return bytesToHex(new Uint8Array(signature))
}

/**
 * Build a JWK representation of the Ed25519 public key.
 */
export function buildJwks(publicKeyHex: string) {
  // Strip the ed25519/ prefix if present
  const rawHex = publicKeyHex.replace(/^ed25519\//, '')
  const publicKeyBytes = hexToBytes(rawHex)

  return {
    keys: [
      {
        kty: 'OKP' as const,
        crv: 'Ed25519' as const,
        x: base64urlEncode(publicKeyBytes),
        use: 'sig' as const,
        kid: 'warden-ed25519-1',
      },
    ],
  }
}

/** Headers worth preserving in the envelope for downstream consumers. */
const RELEVANT_HEADER_PREFIXES = [
  'content-type',
  'x-github-',
  'x-hub-',
  'x-linear-',
  'x-slack-',
  'stripe-',
  'x-request-id',
]

/**
 * Extract relevant upstream headers for the envelope.
 * Drops infrastructure headers (host, connection, etc.) and keeps
 * service-specific headers that downstream consumers may need.
 */
export function extractRelevantHeaders(headers: Headers) {
  const result: Record<string, string> = {}
  headers.forEach((value, key) => {
    const lower = key.toLowerCase()
    if (RELEVANT_HEADER_PREFIXES.some(prefix => lower.startsWith(prefix))) {
      result[key] = value
    }
  })
  return result
}

export function randomId() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

export function tryParseJson(body: ArrayBuffer) {
  try {
    return JSON.parse(new TextDecoder().decode(body))
  } catch {
    return new TextDecoder().decode(body)
  }
}
