/**
 * Biscuit token operations for the auth proxy.
 *
 * Identity-based model:
 * - Authority block: namespaced apw:* identity and rights facts
 * - Attenuation blocks: checks that narrow service/method/path/TTL
 * - Authorizer: ambient request facts plus namespaced identity checks
 * - Credentials DB: source of truth for what services a userId can access
 */

import {
  Biscuit,
  PrivateKey,
  PublicKey,
  AuthorizerBuilder,
  KeyPair,
  SignatureAlgorithm,
} from '@smithery/biscuit'
import type { TokenConstraint } from './core/types'

export const TOKEN_PREFIX = 'apw_'

const RUN_LIMITS = {
  max_facts: 1000,
  max_iterations: 100,
  max_time_micro: 5_000_000, // 5s — generous for normal operation
}

const MAX_AUTHORIZE_RETRIES = 2 // first call may trigger WASM JIT and timeout; retry succeeds

function addPrefix(base64: string): string {
  return TOKEN_PREFIX + base64
}

export function stripPrefix(token: string): string {
  if (token.startsWith(TOKEN_PREFIX)) return token.slice(TOKEN_PREFIX.length)
  return token
}

function escapeDatalog(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function normalizeFactStatement(fact: string): string {
  const trimmed = fact.trim()
  if (!trimmed) return ''
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`
}

export function parseTtlSeconds(ttl: string | number): number {
  if (typeof ttl === 'number') return ttl
  if (/^\d+$/.test(ttl)) return parseInt(ttl, 10)
  const match = ttl.match(/^(\d+)(s|m|h|d)$/)
  if (!match) throw new Error(`Invalid TTL format: ${ttl}`)
  const value = parseInt(match[1], 10)
  const multiplier = ({ s: 1, m: 60, h: 3600, d: 86400 } as const)[
    match[2] as 's' | 'm' | 'h' | 'd'
  ]
  return value * multiplier
}

// ─── Attenuation Block Code ─────────────────────────────────────────────────

/**
 * Build attenuation block code from restriction constraints.
 * Each constraint adds a check that the request must match.
 */
function buildAttenuationCode(constraints: TokenConstraint[]): string {
  const lines: string[] = []
  const alternatives: string[] = []

  for (const c of constraints) {
    const services = toArray(c.services)
    const methods = toArray(c.methods)
    const paths = toArray(c.paths)

    const parts: string[] = []

    if (services.length > 0) {
      const list = services.map(s => `"${escapeDatalog(s)}"`).join(', ')
      parts.push(`resource($r), [${list}].contains($r)`)
    }

    if (methods.length > 0) {
      const list = methods.map(m => `"${escapeDatalog(m.toUpperCase())}"`).join(', ')
      parts.push(`operation($op), [${list}].contains($op)`)
    }

    if (paths.length > 0) {
      const pathChecks = paths.map(p => `$p.starts_with("${escapeDatalog(p)}")`).join(' || ')
      parts.push(`path($p), ${pathChecks}`)
    }

    if (parts.length > 0) {
      alternatives.push(parts.join(', '))
    }
  }

  if (alternatives.length === 1) {
    lines.push(`check if ${alternatives[0]};`)
  } else if (alternatives.length > 1) {
    lines.push(`check if\n  ${alternatives.join('\n  or ')};`)
  }

  // Shortest TTL
  let minTtl: number | undefined
  for (const c of constraints) {
    if (c.ttl !== undefined) {
      const seconds = parseTtlSeconds(c.ttl)
      if (minTtl === undefined || seconds < minTtl) minTtl = seconds
    }
  }
  if (minTtl !== undefined) {
    const expiry = new Date(Date.now() + minTtl * 1000)
    lines.push(`check if time($t), $t <= ${expiry.toISOString()};`)
  }

  return lines.join('\n')
}

// ─── Authorizer Code ─────────────────────────────────────────────────────────

/**
 * Build the authorizer code with ambient facts from the HTTP request.
 */
function buildAuthorizerCode(service: string, method: string, path: string): string {
  return [
    `resource("${escapeDatalog(service)}");`,
    `operation("${escapeDatalog(method.toUpperCase())}");`,
    `path("${escapeDatalog(path)}");`,
    `time(${new Date().toISOString()});`,
    'allow if apw:right("admin");',
    'allow if apw:user_id($u);',
    'allow if apw:org_id($o);',
    'deny if true;',
  ].join('\n')
}

// ─── Public API ──────────────────────────────────────────────────────────────

/** Strip the ed25519/ prefix from a public key hex string */
function stripKeyPrefix(key: string): string {
  return key.replace(/^ed25519\//, '')
}

function parsePublicKey(publicKeyHex: string) {
  return PublicKey.fromString(stripKeyPrefix(publicKeyHex), SignatureAlgorithm.Ed25519)
}

export function getPublicKey(privateKeyHex: string) {
  const pk = PrivateKey.fromString(privateKeyHex)
  return KeyPair.fromPrivateKey(pk).getPublicKey()
}

export function getPublicKeyHex(privateKeyHex: string): string {
  return getPublicKey(privateKeyHex).toString()
}

/**
 * Mint a token with identity, optional rights, and optional extra facts.
 *
 * Authority block contains:
 * - apw:user_id("userId") — identity
 * - apw:right("name") — capabilities (optional)
 * - arbitrary extra facts (optional)
 */
export function mintToken(
  privateKeyHex: string,
  userId: string,
  rights?: string[],
  extraFacts?: string[],
): string {
  const lines: string[] = []
  lines.push(`apw:user_id("${escapeDatalog(userId)}");`)
  for (const r of (rights ?? [])) {
    lines.push(`apw:right("${escapeDatalog(r)}");`)
  }
  for (const fact of (extraFacts ?? []).map(normalizeFactStatement)) {
    if (fact) lines.push(fact)
  }

  const code = lines.join('\n')
  const privateKey = PrivateKey.fromString(privateKeyHex)
  const builder = Biscuit.builder()
  builder.addCode(code)
  const token = builder.build(privateKey)
  return addPrefix(token.toBase64())
}

export function restrictToken(
  tokenBase64: string,
  publicKeyHex: string,
  constraints: TokenConstraint[]
): string {
  const code = buildAttenuationCode(constraints)
  if (!code) return tokenBase64

  const raw = stripPrefix(tokenBase64)
  const publicKey = parsePublicKey(publicKeyHex)
  const token = Biscuit.fromBase64(raw, publicKey)
  const blk = Biscuit.block_builder()
  blk.addCode(code)
  const attenuated = token.appendBlock(blk)
  return addPrefix(attenuated.toBase64())
}

export interface AuthorizationResult {
  authorized: boolean
  error?: string
}

export function authorizeRequest(
  tokenBase64: string,
  publicKeyHex: string,
  service: string,
  method: string,
  path: string
): AuthorizationResult {
  const raw = stripPrefix(tokenBase64)
  const publicKey = parsePublicKey(publicKeyHex)
  const code = buildAuthorizerCode(service, method, path)

  // Retry loop: the first authorizeWithLimits call on a cold worker may timeout
  // because WASM JIT compilation is counted against the time limit. The retry
  // succeeds immediately because the compiled code is cached.
  function attemptAuthorize(retriesLeft: number): AuthorizationResult {
    try {
      const token = Biscuit.fromBase64(raw, publicKey)
      const ab = new AuthorizerBuilder()
      ab.addCode(code)
      const auth = ab.buildAuthenticated(token)
      auth.authorizeWithLimits(RUN_LIMITS)
      return { authorized: true }
    } catch (e) {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : JSON.stringify(e)
      // Only retry on timeout (WASM JIT warmup), not on logic failures
      if (!msg.includes('Timeout') || retriesLeft <= 1) {
        return { authorized: false, error: msg }
      }
      return attemptAuthorize(retriesLeft - 1)
    }
  }

  return attemptAuthorize(MAX_AUTHORIZE_RETRIES)
}

/**
 * Extract token facts from the authority block.
 * Returns namespaced identity, rights, org, audit path, and scopes when present.
 */
export function extractTokenFacts(
  tokenBase64: string,
  publicKeyHex: string,
) {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)

    const rights: string[] = []
    let userId: string | null = null
    let orgId: string | null = null
    let path: string | null = null
    const scopes: string[] = []

    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const apwRightMatch = trimmed.match(/(?:^|[\s,])apw:right\("([^"]+)"\)/)
      if (apwRightMatch) rights.push(apwRightMatch[1])
      const apwUserMatch = trimmed.match(/(?:^|[\s,])apw:user_id\("([^"]+)"\)/)
      if (apwUserMatch) userId = apwUserMatch[1]
      const apwOrgMatch = trimmed.match(/(?:^|[\s,])apw:org_id\("([^"]+)"\)/)
      if (apwOrgMatch) orgId = apwOrgMatch[1]
      const apwPathMatch = trimmed.match(/(?:^|[\s,])apw:path\("([^"]+)"\)/)
      if (apwPathMatch) path = apwPathMatch[1]
      const apwScopeMatch = trimmed.match(/(?:^|[\s,])apw:scope\("([^"]+)"\)/)
      if (apwScopeMatch) scopes.push(apwScopeMatch[1])
    }

    return {
      rights: [...new Set(rights)],
      userId,
      orgId,
      path,
      scopes: [...new Set(scopes)],
    }
  } catch {
    return { rights: [], userId: null, orgId: null, path: null, scopes: [] }
  }
}

/**
 * Extract the userId from the token's apw:user_id fact.
 */
export function extractUserId(
  tokenBase64: string,
  publicKeyHex: string,
): string | null {
  const facts = extractTokenFacts(tokenBase64, publicKeyHex)
  return facts.userId ?? facts.orgId
}

export function getRevocationIds(tokenBase64: string, publicKeyHex: string): string[] {
  const raw = stripPrefix(tokenBase64)
  const publicKey = parsePublicKey(publicKeyHex)
  const token = Biscuit.fromBase64(raw, publicKey)
  return token.getRevocationIdentifiers().map(String)
}

export function generateKeyPairHex(): { privateKey: string; publicKey: string } {
  const kp = new KeyPair(SignatureAlgorithm.Ed25519)
  return {
    privateKey: kp.getPrivateKey().toString(),
    publicKey: kp.getPublicKey().toString(),
  }
}
