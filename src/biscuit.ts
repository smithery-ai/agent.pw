/**
 * Biscuit token operations for the auth proxy.
 *
 * Follows the attenuation-first model:
 * - Authority block: grant facts scoped by service/method/path/metadata
 * - Attenuation blocks: restrict() appends checks that can only narrow
 * - Authorizer: adds ambient facts from the HTTP request, evaluates
 */

import {
  Biscuit,
  PrivateKey,
  PublicKey,
  AuthorizerBuilder,
  KeyPair,
  SignatureAlgorithm,
} from '@smithery/biscuit'
import type { ProxyConstraint } from './core/types'

export const TOKEN_PREFIX = 'wdn_'
const LEGACY_PREFIX = 'vt_'

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
  if (token.startsWith(LEGACY_PREFIX)) return token.slice(LEGACY_PREFIX.length)
  return token
}

function escapeDatalog(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function toArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

export function parseTtlSeconds(ttl: string | number): number {
  if (typeof ttl === 'number') return ttl
  if (/^\d+$/.test(ttl)) return parseInt(ttl, 10)
  const match = ttl.match(/^(\d+)(s|m|h|d)$/)
  if (!match) throw new Error(`Invalid TTL format: ${ttl}`)
  const value = parseInt(match[1], 10)
  switch (match[2]) {
    case 's': return value
    case 'm': return value * 60
    case 'h': return value * 3600
    case 'd': return value * 86400
    default: throw new Error(`Invalid TTL unit: ${match[2]}`)
  }
}

// ─── Authority Block Code ────────────────────────────────────────────────────

/**
 * Build the authority block code from grant constraints.
 *
 * Each grant becomes a set of facts:
 *   grant_service(N, "service"), grant_method(N, "GET"), grant_path(N, "/v4/*"), ...
 *
 * The shortest TTL across all grants is used as the token expiry.
 */
function buildAuthorityCode(grants: ProxyConstraint[]): string {
  const lines: string[] = []

  for (let i = 0; i < grants.length; i++) {
    const grant = grants[i]

    for (const svc of toArray(grant.services)) {
      lines.push(`grant_service(${i}, "${escapeDatalog(svc)}");`)
    }
    if (!grant.services) lines.push(`grant_service(${i}, "*");`)

    for (const method of toArray(grant.methods)) {
      lines.push(`grant_method(${i}, "${escapeDatalog(method.toUpperCase())}");`)
    }
    if (!grant.methods) lines.push(`grant_method(${i}, "*");`)

    for (const path of toArray(grant.paths)) {
      lines.push(`grant_path(${i}, "${escapeDatalog(path)}");`)
    }
    if (!grant.paths) lines.push(`grant_path(${i}, "*");`)

    if (grant.vault) {
      lines.push(`grant_vault(${i}, "${escapeDatalog(grant.vault)}");`)
    }

    if (grant.metadata) {
      for (const [key, value] of Object.entries(grant.metadata)) {
        lines.push(`grant_metadata(${i}, "${escapeDatalog(key)}", "${escapeDatalog(value)}");`)
      }
    }
  }

  // Find shortest TTL
  let minTtl: number | undefined
  for (const grant of grants) {
    if (grant.ttl !== undefined) {
      const seconds = parseTtlSeconds(grant.ttl)
      if (minTtl === undefined || seconds < minTtl) minTtl = seconds
    }
  }
  if (minTtl !== undefined) {
    const expiry = new Date(Date.now() + minTtl * 1000)
    lines.push(`check if time($t), $t <= ${expiry.toISOString()};`)
  }

  return lines.join('\n')
}

// ─── Attenuation Block Code ─────────────────────────────────────────────────

/**
 * Build attenuation block code from restriction constraints.
 * Each constraint adds a check that the request must match.
 */
function buildAttenuationCode(constraints: ProxyConstraint[]): string {
  const lines: string[] = []
  const alternatives: string[] = []

  for (const c of constraints) {
    const services = toArray(c.services)
    const methods = toArray(c.methods)
    const paths = toArray(c.paths)

    const parts: string[] = []

    if (services.length > 0) {
      const list = services.map(s => `"${escapeDatalog(s)}"`).join(', ')
      parts.push(`service($s), [${list}].contains($s)`)
    }

    if (methods.length > 0) {
      const list = methods.map(m => `"${escapeDatalog(m.toUpperCase())}"`).join(', ')
      parts.push(`method($m), [${list}].contains($m)`)
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
    `service("${escapeDatalog(service)}");`,
    `method("${escapeDatalog(method.toUpperCase())}");`,
    `path("${escapeDatalog(path)}");`,
    `time(${new Date().toISOString()});`,
    '',
    '// Rules: a grant matches when all its dimensions match the request',
    'service_ok($gid) <- grant_service($gid, $s), service($s);',
    'service_ok($gid) <- grant_service($gid, "*");',
    'method_ok($gid) <- grant_method($gid, $m), method($m);',
    'method_ok($gid) <- grant_method($gid, "*");',
    'path_ok($gid) <- grant_path($gid, "*");',
    'path_ok($gid) <- grant_path($gid, $p), path($rp), $rp.starts_with($p);',
    'grant_matched($gid) <- service_ok($gid), method_ok($gid), path_ok($gid);',
    '',
    'allow if grant_matched($gid);',
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

export function mintToken(privateKeyHex: string, grants: ProxyConstraint[]): string {
  const code = buildAuthorityCode(grants)
  const privateKey = PrivateKey.fromString(privateKeyHex)
  const builder = Biscuit.builder()
  builder.addCode(code)
  const token = builder.build(privateKey)
  return addPrefix(token.toBase64())
}

export function restrictToken(
  tokenBase64: string,
  publicKeyHex: string,
  constraints: ProxyConstraint[]
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
  let lastError: unknown
  for (let attempt = 0; attempt < MAX_AUTHORIZE_RETRIES; attempt++) {
    try {
      const token = Biscuit.fromBase64(raw, publicKey)
      const ab = new AuthorizerBuilder()
      ab.addCode(code)
      const auth = ab.buildAuthenticated(token)
      auth.authorizeWithLimits(RUN_LIMITS)
      return { authorized: true }
    } catch (e) {
      lastError = e
      const msg = typeof e === 'string' ? e : JSON.stringify(e)
      // Only retry on timeout (WASM JIT warmup), not on logic failures
      if (!msg.includes('Timeout')) {
        return { authorized: false, error: msg }
      }
    }
  }

  const msg = lastError instanceof Error ? lastError.message : typeof lastError === 'string' ? lastError : JSON.stringify(lastError)
  return { authorized: false, error: msg }
}

/**
 * Extract metadata from the authority block's grant_metadata facts.
 * Returns the identity (userId) from the first matching grant.
 */
export function extractIdentityFromToken(
  tokenBase64: string,
  publicKeyHex: string,
  service: string
): string | null {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)

    // Find grant indices that match this service
    const matchingGrants = new Set<number>()
    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const match = trimmed.match(/grant_service\((\d+),\s*"([^"]+)"\)/)
      if (match) {
        const [, id, svc] = match
        if (svc === service || svc === '*') {
          matchingGrants.add(parseInt(id, 10))
        }
      }
    }

    // Extract userId from matching grant's metadata
    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const match = trimmed.match(/grant_metadata\((\d+),\s*"userId",\s*"([^"]+)"\)/)
      if (match) {
        const [, id, userId] = match
        if (matchingGrants.has(parseInt(id, 10))) {
          return userId
        }
      }
    }

    return null
  } catch {
    return null
  }
}

/**
 * Extract all grant info from a token for discoverability.
 */
export function extractGrants(
  tokenBase64: string,
  publicKeyHex: string
): { services: string[]; methods: string[]; paths: string[] }[] {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)
    const grants = new Map<number, { services: string[]; methods: string[]; paths: string[] }>()

    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')

      const serviceMatch = trimmed.match(/grant_service\((\d+),\s*"([^"]+)"\)/)
      if (serviceMatch) {
        const gid = parseInt(serviceMatch[1], 10)
        if (!grants.has(gid)) grants.set(gid, { services: [], methods: [], paths: [] })
        grants.get(gid)!.services.push(serviceMatch[2])
      }

      const methodMatch = trimmed.match(/grant_method\((\d+),\s*"([^"]+)"\)/)
      if (methodMatch) {
        const gid = parseInt(methodMatch[1], 10)
        if (!grants.has(gid)) grants.set(gid, { services: [], methods: [], paths: [] })
        grants.get(gid)!.methods.push(methodMatch[2])
      }

      const pathMatch = trimmed.match(/grant_path\((\d+),\s*"([^"]+)"\)/)
      if (pathMatch) {
        const gid = parseInt(pathMatch[1], 10)
        if (!grants.has(gid)) grants.set(gid, { services: [], methods: [], paths: [] })
        grants.get(gid)!.paths.push(pathMatch[2])
      }
    }

    return Array.from(grants.values())
  } catch {
    return []
  }
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

// ─── Management Tokens ──────────────────────────────────────────────────────

export function mintManagementToken(
  privateKeyHex: string,
  rights: string[],
  vaultAdminSlugs: string[],
): string {
  const lines: string[] = []
  for (const r of rights) {
    lines.push(`right("${escapeDatalog(r)}");`)
  }
  for (const slug of vaultAdminSlugs) {
    lines.push(`vault_admin("${escapeDatalog(slug)}");`)
  }
  const code = lines.join('\n')
  const privateKey = PrivateKey.fromString(privateKeyHex)
  const builder = Biscuit.builder()
  builder.addCode(code)
  const token = builder.build(privateKey)
  return addPrefix(token.toBase64())
}

export function extractManagementRights(
  tokenBase64: string,
  publicKeyHex: string,
) {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)

    const rights: string[] = []
    const vaultAdminSlugs: string[] = []

    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const rightMatch = trimmed.match(/right\("([^"]+)"\)/)
      if (rightMatch) rights.push(rightMatch[1])
      const vaultAdminMatch = trimmed.match(/vault_admin\("([^"]+)"\)/)
      if (vaultAdminMatch) vaultAdminSlugs.push(vaultAdminMatch[1])
    }

    return { rights, vaultAdminSlugs }
  } catch {
    return { rights: [], vaultAdminSlugs: [] }
  }
}

/**
 * Extract the first vault from any grant in the token, regardless of service.
 * Useful for listing webhook registrations across all services.
 */
export function extractFirstVault(
  tokenBase64: string,
  publicKeyHex: string,
): string | null {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)

    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const match = trimmed.match(/grant_vault\(\d+,\s*"([^"]+)"\)/)
      if (match) {
        return match[1]
      }
    }

    return null
  } catch {
    return null
  }
}

export function extractVaultFromToken(
  tokenBase64: string,
  publicKeyHex: string,
  service: string,
): string | null {
  try {
    const raw = stripPrefix(tokenBase64)
    const publicKey = parsePublicKey(publicKeyHex)
    const token = Biscuit.fromBase64(raw, publicKey)
    const source = token.getBlockSource(0)

    const matchingGrants = new Set<number>()
    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const match = trimmed.match(/grant_service\((\d+),\s*"([^"]+)"\)/)
      if (match) {
        const [, id, svc] = match
        if (svc === service || svc === '*') {
          matchingGrants.add(parseInt(id, 10))
        }
      }
    }

    for (const line of source.split('\n')) {
      const trimmed = line.trim().replace(/;$/, '')
      const match = trimmed.match(/grant_vault\((\d+),\s*"([^"]+)"\)/)
      if (match) {
        const [, id, vault] = match
        if (matchingGrants.has(parseInt(id, 10))) {
          return vault
        }
      }
    }

    return null
  } catch {
    return null
  }
}
