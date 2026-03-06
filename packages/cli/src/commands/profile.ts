import { readFileSync } from 'node:fs'
import { requestJson, request } from '../http'

interface CredProfile {
  slug: string
  host: string[]
  displayName?: string | null
  description?: string | null
  auth?: unknown | null
}

interface CreateCredProfileRequest {
  host: string[]
  auth?: Record<string, unknown>
  managedOauth?: Record<string, unknown>
  displayName?: string
  description?: string
}

interface AddProfileOptions {
  filePath?: string
  auth?: string
  headers?: string[]
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

export async function listProfiles() {
  const profiles = await requestJson<CredProfile[]>('/cred_profiles')

  if (profiles.length === 0) {
    console.log('No credential profiles configured.')
    return
  }

  console.log(`${'SLUG'.padEnd(24)}${'HOSTS'.padEnd(40)}DESCRIPTION`)
  for (const profile of profiles) {
    const hosts = profile.host.join(', ')
    const desc = profile.description ? profile.description.slice(0, 40) : ''
    console.log(`${profile.slug.padEnd(24)}${hosts.padEnd(40)}${desc}`)
  }
}

export async function getProfileCmd(slug: string) {
  try {
    const profile = await requestJson<CredProfile>(`/cred_profiles/${encodeURIComponent(slug)}`)
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
  let body: CreateCredProfileRequest

  if (options.filePath) {
    const content = readFileSync(options.filePath, 'utf-8')
    body = JSON.parse(content) as CreateCredProfileRequest
    if ((!body.host || body.host.length === 0) && hosts.length > 0) {
      body.host = hosts
    }
  } else if (options.auth === 'headers') {
    if (hosts.length === 0) {
      console.error('At least one --host is required.')
      process.exit(1)
    }
    const fields = (options.headers ?? []).map(parseHeaderFieldTemplate)
    if (fields.length === 0) {
      console.error('At least one -H/--header template is required for --auth headers.')
      process.exit(1)
    }
    body = {
      host: hosts,
      auth: {
        kind: 'headers',
        fields,
      },
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
  console.log(`Credential profile '${slug}' registered.`)
}

export async function removeProfile(slug: string) {
  try {
    const res = await request(`/cred_profiles/${encodeURIComponent(slug)}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const error = new Error(await res.text()) as Error & { status?: number }
      error.status = res.status
      throw error
    }
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
