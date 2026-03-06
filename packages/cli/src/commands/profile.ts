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

export async function addProfile(slug: string, hosts: string[], filePath?: string) {
  let body: CreateCredProfileRequest

  if (filePath) {
    const content = readFileSync(filePath, 'utf-8')
    body = JSON.parse(content) as CreateCredProfileRequest
    if ((!body.host || body.host.length === 0) && hosts.length > 0) {
      body.host = hosts
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
