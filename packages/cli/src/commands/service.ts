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

interface AddServiceOptions {
  filePath?: string
  auth?: string
  headers?: string[]
  displayName?: string
  description?: string
  docsUrl?: string
  authorizeUrl?: string
  tokenUrl?: string
  scopes?: string[]
  identityUrl?: string
  identityPath?: string
  clientId?: string
  clientSecret?: string
}

interface HeaderFieldTemplate {
  header: string
  prefix?: string
  name: string
  description: string
}

function parseHeaderFieldTemplate(spec: string): HeaderFieldTemplate {
  const idx = spec.indexOf(':')
  if (idx === -1) {
    throw new Error(`Invalid header template: ${spec}. Use "Header: Prefix {field:Description}".`)
  }

  const header = spec.slice(0, idx).trim()
  const value = spec.slice(idx + 1).trim()
  const open = value.indexOf('{')
  const close = value.lastIndexOf('}')
  if (!header || open === -1 || close <= open) {
    throw new Error(`Invalid header template: ${spec}. Use "Header: Prefix {field:Description}".`)
  }

  const fieldSpec = value.slice(open + 1, close)
  const fieldIdx = fieldSpec.indexOf(':')
  if (fieldIdx === -1) {
    throw new Error(`Invalid header field: ${spec}. Use "{field:Description}".`)
  }

  const name = fieldSpec.slice(0, fieldIdx).trim()
  const description = fieldSpec.slice(fieldIdx + 1).trim()
  if (!name || !description) {
    throw new Error(`Invalid header field: ${spec}. Use "{field:Description}".`)
  }

  const prefix = value.slice(0, open)
  return {
    header,
    prefix: prefix.length > 0 ? prefix : undefined,
    name,
    description,
  }
}

function buildHeaderAuthSchemes(fields: HeaderFieldTemplate[]) {
  const first = fields[0]
  if (!first) return undefined
  if (first.header.toLowerCase() === 'authorization') {
    if (first.prefix === 'Bearer ') return [{ type: 'http', scheme: 'bearer' as const }]
    if (first.prefix === 'Basic ') return [{ type: 'http', scheme: 'basic' as const }]
  }
  return [{ type: 'apiKey' as const, in: 'header' as const, name: first.header }]
}

function buildOAuthConfig(options: AddServiceOptions) {
  if (!options.authorizeUrl || !options.tokenUrl) {
    console.error('OAuth services require --authorize-url and --token-url.')
    process.exit(1)
  }

  return {
    authorizeUrl: options.authorizeUrl,
    tokenUrl: options.tokenUrl,
    scopes: options.scopes && options.scopes.length > 0 ? options.scopes.join(' ') : undefined,
  }
}

function buildAuthExtras(options: AddServiceOptions) {
  const extras: Record<string, unknown> = {}
  if (options.identityUrl) extras.identity_url = options.identityUrl
  if (options.identityPath) extras.identity_path = options.identityPath
  if (options.docsUrl) extras.docsUrl = options.docsUrl
  return extras
}

function toCredProfileRequest(
  legacy: LegacyCreateServiceRequest,
  fallbackHosts: string[],
): CreateCredProfileRequest {
  const allowedHosts = legacy.allowedHosts && legacy.allowedHosts.length > 0
    ? legacy.allowedHosts
    : fallbackHosts

  if (allowedHosts.length === 0) {
    console.error('At least one --host is required.')
    process.exit(1)
  }

  const auth: Record<string, unknown> = {}
  if (legacy.authSchemes) auth.authSchemes = legacy.authSchemes
  if (legacy.authConfig) Object.assign(auth, legacy.authConfig)
  if (legacy.docsUrl) auth.docsUrl = legacy.docsUrl

  const managedOauth: Record<string, unknown> = {}
  if (legacy.oauthClientId) managedOauth.clientId = legacy.oauthClientId
  if (legacy.oauthClientSecret) managedOauth.clientSecret = legacy.oauthClientSecret

  return {
    host: allowedHosts,
    auth: Object.keys(auth).length > 0 ? auth : undefined,
    managedOauth: Object.keys(managedOauth).length > 0 ? managedOauth : undefined,
    displayName: legacy.displayName,
    description: legacy.description,
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

export async function addService(slug: string, hosts: string[], options: AddServiceOptions = {}) {
  let body: CreateCredProfileRequest

  if (options.filePath) {
    const content = readFileSync(options.filePath, 'utf-8')
    const parsed = JSON.parse(content) as CreateCredProfileRequest | LegacyCreateServiceRequest
    if ('host' in parsed) {
      body = parsed as CreateCredProfileRequest
      if ((!body.host || body.host.length === 0) && hosts.length > 0) {
        body.host = hosts
      }
    } else {
      body = toCredProfileRequest(parsed as LegacyCreateServiceRequest, hosts)
    }
  } else {
    if (hosts.length === 0) {
      console.error('At least one --host is required.')
      process.exit(1)
    }

    let auth: Record<string, unknown> | undefined
    if (options.auth === 'headers') {
      const fields = (options.headers ?? []).map(parseHeaderFieldTemplate)
      if (fields.length === 0) {
        console.error('At least one -H/--header template is required for --auth headers.')
        process.exit(1)
      }

      auth = {
        kind: 'headers',
        fields,
        authSchemes: buildHeaderAuthSchemes(fields),
        ...buildAuthExtras(options),
      }
    } else if (options.auth === 'oauth') {
      auth = {
        kind: 'oauth',
        ...buildOAuthConfig(options),
        ...buildAuthExtras(options),
      }
    }

    const managedOauth: Record<string, unknown> = {}
    if (options.clientId) managedOauth.clientId = options.clientId
    if (options.clientSecret) managedOauth.clientSecret = options.clientSecret

    body = {
      host: hosts,
      auth,
      managedOauth: Object.keys(managedOauth).length > 0 ? managedOauth : undefined,
      displayName: options.displayName,
      description: options.description,
    }
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
