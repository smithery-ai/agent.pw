import { readFileSync } from 'node:fs'
import { collectAllPages, getClient, pageToPaginatedResponse, type PaginatedResponse } from '../http'
import { output, outputList, outputListPage } from '../output'

interface CredProfile {
  path: string
  host: string[] | string | null
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

export interface ListProfilesOptions {
  limit?: number
  cursor?: string
  all?: boolean
}

export interface AddProfileOptions {
  filePath?: string
  auth?: string
  headers?: string[]
  scopes?: string[]
  displayName?: string
  description?: string
  docsUrl?: string
  authorizeUrl?: string
  tokenUrl?: string
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

function buildOAuthConfig(options: AddProfileOptions) {
  if (!options.authorizeUrl || !options.tokenUrl) {
    console.error('OAuth profiles require --authorize-url and --token-url.')
    process.exit(1)
  }
  return {
    authorizeUrl: options.authorizeUrl,
    tokenUrl: options.tokenUrl,
    scopes: options.scopes && options.scopes.length > 0 ? options.scopes.join(' ') : undefined,
  }
}

function buildAuthExtras(options: AddProfileOptions) {
  const extras: Record<string, unknown> = {}
  if (options.identityUrl) extras.identity_url = options.identityUrl
  if (options.identityPath) extras.identity_path = options.identityPath
  if (options.docsUrl) extras.docsUrl = options.docsUrl
  return extras
}

function printProfileTable(profiles: CredProfile[]) {
  if (profiles.length === 0) {
    console.log('No credential profiles configured.')
    return
  }

  console.log(`${'SLUG'.padEnd(24)}${'HOSTS'.padEnd(40)}DESCRIPTION`)
  for (const profile of profiles) {
    const hosts = Array.isArray(profile.host)
      ? profile.host.join(', ')
      : typeof profile.host === 'string'
        ? profile.host
        : ''
    const desc = profile.description ? profile.description.slice(0, 40) : ''
    console.log(`${profile.path.padEnd(24)}${hosts.padEnd(40)}${desc}`)
  }
}

function printNextPageHint(page: PaginatedResponse<unknown>) {
  if (!page.hasMore || !page.nextCursor) return
  console.log(`\nNext cursor: ${page.nextCursor}`)
  console.log('More results available. Re-run with `--cursor <cursor>` or `--all`.')
}

export async function listProfiles(options: ListProfilesOptions = {}) {
  const client = await getClient()

  if (options.all) {
    const profiles = await collectAllPages<CredProfile>(client.profiles.list({ limit: options.limit }))

    if (outputList(profiles)) return
    printProfileTable(profiles)
    return
  }

  const page = await pageToPaginatedResponse<CredProfile>(client.profiles.list({
    limit: options.limit,
    cursor: options.cursor,
  }))

  if (outputListPage(page)) return
  printProfileTable(page.data)
  printNextPageHint(page)
}

export async function getProfileCmd(slug: string) {
  const client = await getClient()
  try {
    const profile = await client.profiles.get(slug)
    if (output(profile)) return
    console.log(JSON.stringify(profile, null, 2))
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Credential profile '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

export async function addProfile(slug: string, hosts: string[], options: AddProfileOptions = {}) {
  const client = await getClient()
  let body: CreateCredProfileRequest

  if (options.filePath) {
    const content = readFileSync(options.filePath, 'utf-8')
    body = JSON.parse(content) as CreateCredProfileRequest
    if ((!body.host || body.host.length === 0) && hosts.length > 0) {
      body.host = hosts
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

  const result = await client.profiles.create(slug, body)
  if (output(result)) return
  console.log(`Credential profile '${slug}' registered.`)
}

export async function removeProfile(slug: string) {
  const client = await getClient()
  try {
    await client.profiles.delete(slug)
    if (output({ slug, removed: true })) return
    console.log(`Credential profile '${slug}' removed.`)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Credential profile '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 404
}
