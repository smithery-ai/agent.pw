import { readFileSync } from 'node:fs'
import { requestJson, request } from '../http'

interface LegacyService {
  slug: string
  allowedHosts: string[]
  displayName?: string | null
  description?: string | null
  authSchemes?: unknown[] | null
  docsUrl?: string | null
}

interface LegacyCreateServiceRequest {
  allowedHosts?: string[]
  authSchemes?: unknown[]
  displayName?: string
  description?: string
  oauthClientId?: string
  oauthClientSecret?: string
  docsUrl?: string
  authConfig?: Record<string, unknown>
}

interface CredProfile {
  slug: string
  host: string[]
  displayName?: string | null
  description?: string | null
  auth?: Record<string, unknown> | null
}

interface CreateCredProfileRequest {
  host: string[]
  auth?: Record<string, unknown>
  managedOauth?: Record<string, unknown>
  displayName?: string
  description?: string
}

function toLegacyService(profile: CredProfile): LegacyService {
  return {
    slug: profile.slug,
    allowedHosts: profile.host,
    displayName: profile.displayName,
    description: profile.description,
    authSchemes: Array.isArray(profile.auth?.authSchemes)
      ? (profile.auth.authSchemes as unknown[])
      : null,
    docsUrl: typeof profile.auth?.docsUrl === 'string' ? profile.auth.docsUrl : null,
  }
}

export async function listServices() {
  const profiles = await requestJson<CredProfile[]>('/cred_profiles')
  const services = profiles.map(toLegacyService)

  if (services.length === 0) {
    console.log('No services registered.')
    return
  }

  console.log(`${'SLUG'.padEnd(20)}${'HOSTS'.padEnd(40)}DESCRIPTION`)
  for (const service of services) {
    const hosts = service.allowedHosts.join(', ')
    const desc = service.description ? service.description.slice(0, 40) : ''
    console.log(`${service.slug.padEnd(20)}${hosts.padEnd(40)}${desc}`)
  }
}

export async function getServiceCmd(slug: string) {
  try {
    const profile = await requestJson<CredProfile>(`/cred_profiles/${encodeURIComponent(slug)}`)
    console.log(JSON.stringify(toLegacyService(profile), null, 2))
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Service '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

export async function addService(slug: string, hosts: string[], filePath?: string) {
  let body: CreateCredProfileRequest

  if (filePath) {
    const content = readFileSync(filePath, 'utf-8')
    const legacy = JSON.parse(content) as LegacyCreateServiceRequest
    const allowedHosts = legacy.allowedHosts && legacy.allowedHosts.length > 0
      ? legacy.allowedHosts
      : hosts

    if (allowedHosts.length === 0) {
      console.error('At least one --host is required.')
      process.exit(1)
    }

    const auth: Record<string, unknown> = {}
    if (legacy.authSchemes) auth.authSchemes = legacy.authSchemes
    if (legacy.authConfig) auth.authConfig = legacy.authConfig
    if (legacy.docsUrl) auth.docsUrl = legacy.docsUrl

    const managedOauth: Record<string, unknown> = {}
    if (legacy.oauthClientId) managedOauth.clientId = legacy.oauthClientId
    if (legacy.oauthClientSecret) managedOauth.clientSecret = legacy.oauthClientSecret

    body = {
      host: allowedHosts,
      auth: Object.keys(auth).length > 0 ? auth : undefined,
      managedOauth: Object.keys(managedOauth).length > 0 ? managedOauth : undefined,
      displayName: legacy.displayName,
      description: legacy.description,
    }
  } else {
    if (hosts.length === 0) {
      console.error('At least one --host is required.')
      process.exit(1)
    }
    body = { host: hosts }
  }

  await requestJson(`/cred_profiles/${encodeURIComponent(slug)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  console.log(`Service '${slug}' registered.`)
}

export async function removeService(slug: string) {
  try {
    const res = await request(`/cred_profiles/${encodeURIComponent(slug)}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const error = new Error(await res.text()) as Error & { status?: number }
      error.status = res.status
      throw error
    }
    console.log(`Service '${slug}' removed.`)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Service '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 404
}
