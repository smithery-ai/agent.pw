import { createInterface } from 'node:readline'
import { request, requestJson } from '../http'
import { output, outputList } from '../output'

interface ListedCredential {
  name: string
  host: string
  path: string
  createdAt: string
}

interface CredProfile {
  path: string
  host: string[]
}

interface AddCredOptions {
  auth?: string
  credentialName?: string
  headers?: string[]
}

interface RemoveCredOptions {
  host?: string
  path?: string
  profile?: string
}

function relativeTime(date: string) {
  const diff = Date.now() - new Date(date).getTime()
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export async function listCreds() {
  const creds = await requestJson<ListedCredential[]>('/credentials')

  if (outputList(creds)) return

  if (creds.length === 0) {
    console.log('No credentials stored. Add one with `agent.pw cred add <profile-or-host>`.')
    return
  }

  console.log(`${'HOST'.padEnd(28)}${'NAME'.padEnd(20)}${'PATH'.padEnd(32)}ADDED`)
  for (const cr of creds) {
    const added = cr.createdAt ? relativeTime(cr.createdAt) : ''
    console.log(`${cr.host.padEnd(28)}${cr.name.padEnd(20)}${cr.path.padEnd(32)}${added}`)
  }
}

async function resolveProfile(target: string): Promise<CredProfile | null> {
  try {
    return await requestJson<CredProfile>(`/cred_profiles/${encodeURIComponent(target)}`)
  } catch (e: unknown) {
    if (!isNotFound(e)) throw e
  }

  const profiles = await requestJson<CredProfile[]>('/cred_profiles')
  return profiles.find(profile => profile.host.includes(target)) ?? null
}

function targetToCredentialName(target: string) {
  const sanitized = target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  return sanitized || 'credential'
}

function parseHeaders(headerSpecs: string[]) {
  const headers: Record<string, string> = {}
  for (const spec of headerSpecs) {
    const idx = spec.indexOf(':')
    if (idx === -1) {
      throw new Error(`Invalid header: ${spec}. Use "Header-Name: value".`)
    }
    const name = spec.slice(0, idx).trim()
    const value = spec.slice(idx + 1).trim()
    if (!name || !value) {
      throw new Error(`Invalid header: ${spec}. Use "Header-Name: value".`)
    }
    headers[name] = value
  }
  return headers
}

function profileName(profile: CredProfile) {
  const path = profile.path
  const lastSlash = path.lastIndexOf('/')
  return lastSlash >= 0 ? path.slice(lastSlash + 1) : path
}

export async function addCred(target: string, value?: string, options: AddCredOptions = {}) {
  const profile = await resolveProfile(target)
  const manualHeaders = options.headers && options.headers.length > 0 ? parseHeaders(options.headers) : undefined
  const credentialName = options.credentialName ?? (profile ? profileName(profile) : targetToCredentialName(target))

  if (!manualHeaders && !value) {
    const rl = createInterface({ input: process.stdin, output: process.stderr })
    value = await new Promise<string>(resolve => {
      rl.question('Paste your API key: ', answer => {
        rl.close()
        resolve(answer.trim())
      })
    })
    if (!value) {
      console.error('No value provided.')
      process.exit(1)
    }
  }

  await requestJson(`/credentials/${encodeURIComponent(credentialName)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: manualHeaders ? undefined : value,
      headers: manualHeaders,
      host: profile ? undefined : target,
      profile: profile ? profileName(profile) : undefined,
      auth: options.auth,
    }),
  })

  const resolvedHost = profile?.host[0] ?? target
  console.log(`Stored credential '${credentialName}' for ${resolvedHost}.`)
}

export async function removeCred(name: string, options: RemoveCredOptions = {}) {
  try {
    const profile = options.profile ? await resolveProfile(options.profile) : await resolveProfile(name)
    const host = options.host ?? profile?.host[0]
    if (!host) {
      console.error('Host is required to remove a credential. Pass --host <hostname> for manual credentials.')
      process.exit(1)
    }

    const params = new URLSearchParams({ host })
    if (options.path) params.set('path', options.path)

    const res = await request(`/credentials/${encodeURIComponent(name)}?${params.toString()}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const error = new Error(await res.text()) as Error & { status?: number }
      error.status = res.status
      throw error
    }
    console.log(`Removed credential '${name}'.`)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`No credential found for '${name}'.`)
      process.exit(1)
    }
    throw e
  }
}

function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 404
}
