import { loadBiscuit } from '../biscuit'
import { getClient, requestJson } from '../http'
import { resolve } from '../resolve'
import { readTokenStack, writeTokenStack } from '../config'
import { output } from '../output'

const TOKEN_PREFIX = 'apw_'

function base64urlToHex(b64url: string) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  return Array.from(bin, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

async function fetchPublicKeyHex(serverUrl: string) {
  const res = await fetch(`${serverUrl.replace(/\/$/, '')}/.well-known/jwks.json`)
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`)
  const jwks = await res.json() as { keys: Array<{ x: string }> }
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

interface RestrictOptions {
  services?: string[]
  methods?: string[]
  paths?: string[]
  ttl?: string
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

  const res = await requestJson<{ token: string }>('/tokens/restrict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ constraints: [constraint] }),
  })

  if (output(res)) return
  console.log(res.token)
}

export async function revokeTokenCmd() {
  const client = await getClient()
  await client.tokens.revoke({})
  console.log('Token revoked.')
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

  const res = await requestJson<{ token: string }>('/tokens/restrict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ constraints: [constraint] }),
  })

  const stack = readTokenStack()
  stack.push(res.token)
  writeTokenStack(stack)
  console.log(`Pushed restricted token (stack depth: ${stack.length})`)
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
