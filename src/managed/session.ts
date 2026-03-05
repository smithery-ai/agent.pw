/**
 * Encrypted cookie-based session management.
 * Uses AES-256-GCM, same pattern as credentials-crypto.ts.
 */

export interface Session {
  workosUserId: string
  orgId: string
  email: string
  name?: string
  exp: number // Unix timestamp (seconds)
}

const COOKIE_NAME = 'wdn_session'
const SESSION_TTL_SECONDS = 86400 // 24 hours

async function importKey(secret: string): Promise<CryptoKey> {
  const raw = new Uint8Array(Buffer.from(secret, 'base64'))
  if (raw.length !== 32) throw new Error('Session secret must be 32 bytes')
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

async function encryptSession(secret: string, session: Session): Promise<string> {
  const key = await importKey(secret)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify(session))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  const combined = new Uint8Array(12 + ciphertext.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ciphertext), 12)
  return btoa(String.fromCharCode(...combined))
}

async function decryptSession(secret: string, encrypted: string): Promise<Session | null> {
  try {
    const key = await importKey(secret)
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0))
    if (raw.length < 12 + 16) return null
    const iv = raw.subarray(0, 12)
    const ciphertext = raw.subarray(12)
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
    return JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    return null
  }
}

export async function getSessionFromCookie(
  cookieHeader: string | undefined,
  secret: string,
): Promise<Session | null> {
  if (!cookieHeader) return null
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`))
  if (!match) return null
  const session = await decryptSession(secret, decodeURIComponent(match[1]))
  if (!session) return null
  if (session.exp < Date.now() / 1000) return null
  return session
}

export async function buildSetCookieHeader(secret: string, session: Session): Promise<string> {
  const value = await encryptSession(secret, session)
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`
}

export { SESSION_TTL_SECONDS }
