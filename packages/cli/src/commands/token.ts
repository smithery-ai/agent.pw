import { loadBiscuit } from '../biscuit'
import { requestJson } from '../http'
import { readTokenStack, writeTokenStack } from '../config'
import { output, outputList } from '../output'
import { resolve } from '../resolve'
import { isRecord } from '../type-utils'

const TOKEN_PREFIX = 'apw_'

function normalizeProvidedToken(token: string) {
  const trimmed = token.trim()
  if (!trimmed) {
    console.error('Token is required.')
    process.exit(1)
  }
  if (!trimmed.startsWith(TOKEN_PREFIX)) {
    console.error(`Token must start with ${TOKEN_PREFIX}`)
    process.exit(1)
  }
  return trimmed
}

function base64urlToHex(b64url: string) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

function isJwksResponse(value: unknown): value is { keys: Array<{ x: string }> } {
  return isRecord(value)
    && Array.isArray(value.keys)
    && value.keys.every(key => isRecord(key) && typeof key.x === 'string')
}

async function fetchPublicKeyHex(serverUrl: string) {
  const res = await fetch(`${serverUrl.replace(/\/$/, '')}/.well-known/jwks.json`)
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`)
  const jwks = await res.json()
  if (!isJwksResponse(jwks) || jwks.keys.length === 0) {
    throw new Error('Failed to fetch JWKS: invalid response body')
  }
  return base64urlToHex(jwks.keys[0].x)
}

export async function inspectTokenCmd() {
  const { Biscuit, PublicKey, SignatureAlgorithm } = await loadBiscuit()
  const { url, token } = await resolve()
  const publicKeyHex = await fetchPublicKeyHex(url)

  const raw = token.startsWith(TOKEN_PREFIX) ? token.slice(TOKEN_PREFIX.length) : token
  const publicKey = PublicKey.fromString(publicKeyHex, SignatureAlgorithm.Ed25519)
  const biscuit = Biscuit.fromBase64(raw, publicKey)

  // Parse structured facts from authority block
  const authority = biscuit.getBlockSource(0)
  let userId: string | null = null
  let orgId: string | null = null
  const rights: string[] = []
  const scopes: string[] = []

  for (const line of authority.split('\n')) {
    const t = line.trim().replace(/;$/, '')
    const userMatch = t.match(/user_id\("([^"]+)"\)/)
    if (userMatch) userId = userMatch[1]
    const orgMatch = t.match(/org_id\("([^"]+)"\)/)
    if (orgMatch) orgId = orgMatch[1]
    const rightMatch = t.match(/right\("([^"]+)",\s*"([^"]+)"\)/)
    if (rightMatch) {
      const right = `${rightMatch[2]}@${rightMatch[1]}`
      if (!rights.includes(right)) rights.push(right)
    }
    const scopeMatch = t.match(/scope\("([^"]+)"\)/)
    if (scopeMatch && !scopes.includes(scopeMatch[1])) scopes.push(scopeMatch[1])
  }

  // Print summary
  const stack = readTokenStack()
  if (stack.length > 0) console.log(`Stack:   depth ${stack.length}`)
  if (userId) console.log(`User:    ${userId}`)
  if (orgId) console.log(`Org:     ${orgId}`)
  console.log(`Rights:  ${rights.length > 0 ? rights.join(', ') : '(none)'}`)
  if (scopes.length > 0) console.log(`Scopes:  ${scopes.join(', ')}`)

  // Print blocks
  console.log()
  console.log('Authority block:')
  for (const line of authority.split('\n')) {
    if (line.trim()) console.log(`  ${line.trim()}`)
  }

  // Print attenuation blocks
  const blockCount = biscuit.countBlocks()
  for (let i = 1; i < blockCount; i++) {
    const source = biscuit.getBlockSource(i)
    console.log()
    console.log(`Block ${i} (attenuation):`)
    for (const line of source.split('\n')) {
      if (line.trim()) console.log(`  ${line.trim()}`)
    }
  }
}

export function pushProvidedTokenCmd(token: string) {
  const normalizedToken = normalizeProvidedToken(token)
  const stack = readTokenStack()
  stack.push(normalizedToken)
  writeTokenStack(stack)
  console.log(`Pushed provided token (stack depth: ${stack.length}). Run \`agent.pw token pop\` to restore the previous token.`)
}

interface RestrictOptions {
  services?: string[]
  methods?: string[]
  paths?: string[]
  ttl?: string
}

interface IssuedTokenRecord {
  id: string
  name: string | null
  rights: Array<{ action: string; root: string }>
  constraints: Array<Record<string, unknown>>
  createdAt: string
  expiresAt: string | null
  lastUsedAt: string | null
  revokedAt: string | null
  revokeReason: string | null
}

interface CreateTokenResponse extends IssuedTokenRecord {
  ok: true
  token: string
}

function describeStatus(token: IssuedTokenRecord) {
  if (token.revokedAt) return 'revoked'
  if (token.expiresAt && new Date(token.expiresAt).getTime() <= Date.now()) return 'expired'
  return 'active'
}

function formatTimestamp(value: string | null) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toISOString()
}

function printIssuedToken(token: IssuedTokenRecord) {
  const label = token.name ? ` ${token.name}` : ''
  console.log(`${token.id}${label}`)
  console.log(`  status: ${describeStatus(token)}`)
  console.log(`  created: ${formatTimestamp(token.createdAt)}`)
  console.log(`  expires: ${formatTimestamp(token.expiresAt)}`)
  console.log(`  last used: ${formatTimestamp(token.lastUsedAt)}`)
  console.log(`  rights: ${token.rights.map(right => `${right.action}@${right.root}`).join(', ') || '(none)'}`)
  if (token.revokeReason) {
    console.log(`  revoke reason: ${token.revokeReason}`)
  }
}

async function createTrackedToken(constraint: Record<string, unknown>) {
  return requestJson<CreateTokenResponse>('/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ constraints: [constraint] }),
  })
}

export async function restrictTokenCmd(opts: RestrictOptions) {
  const constraint: Record<string, unknown> = {}
  if (opts.services && opts.services.length > 0) {
    constraint.services = opts.services.length === 1 ? opts.services[0] : opts.services
  }
  if (opts.methods && opts.methods.length > 0) {
    const upper = opts.methods.map(m => m.toUpperCase())
    constraint.methods = upper.length === 1 ? upper[0] : upper
  }
  if (opts.paths && opts.paths.length > 0) {
    constraint.paths = opts.paths.length === 1 ? opts.paths[0] : opts.paths
  }
  if (opts.ttl) constraint.ttl = opts.ttl

  if (Object.keys(constraint).length === 0) {
    console.error('At least one constraint is required (--service, --method, --path, or --ttl).')
    process.exit(1)
  }

  const res = await createTrackedToken(constraint)

  if (output(res)) return
  console.log(res.token)
}

export async function listTokensCmd() {
  const res = await requestJson<{ data: IssuedTokenRecord[] }>('/tokens', {
    method: 'GET',
  })

  if (outputList(res.data)) return
  if (res.data.length === 0) {
    console.log('No issued tokens.')
    return
  }

  for (const token of res.data) {
    printIssuedToken(token)
  }
}

export async function revokeTokenCmd(id: string, reason?: string) {
  const res = await requestJson<{ ok: true; id: string }>('/tokens/' + encodeURIComponent(id), {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(reason ? { reason } : {}),
  })

  if (output(res)) return
  console.log(`Revoked token ${res.id}.`)
}

export async function pushTokenCmd(opts: RestrictOptions) {
  const constraint: Record<string, unknown> = {}
  if (opts.services && opts.services.length > 0) {
    constraint.services = opts.services.length === 1 ? opts.services[0] : opts.services
  }
  if (opts.methods && opts.methods.length > 0) {
    const upper = opts.methods.map(m => m.toUpperCase())
    constraint.methods = upper.length === 1 ? upper[0] : upper
  }
  if (opts.paths && opts.paths.length > 0) {
    constraint.paths = opts.paths.length === 1 ? opts.paths[0] : opts.paths
  }
  if (opts.ttl) constraint.ttl = opts.ttl

  if (Object.keys(constraint).length === 0) {
    console.error('At least one constraint is required (--service, --method, --path, or --ttl).')
    process.exit(1)
  }

  const res = await createTrackedToken(constraint)

  const stack = readTokenStack()
  stack.push(res.token)
  writeTokenStack(stack)
  console.log(`Pushed tracked token ${res.id} (stack depth: ${stack.length}). Run \`agent.pw token pop\` to restore the previous token.`)
}

export function popTokenCmd() {
  const stack = readTokenStack()
  if (stack.length === 0) {
    console.error('Token stack is empty — already at root token.')
    process.exit(1)
  }
  stack.pop()
  writeTokenStack(stack)
  if (stack.length === 0) {
    console.log('Popped to root token.')
  } else {
    console.log(`Popped token (stack depth: ${stack.length})`)
  }
}
