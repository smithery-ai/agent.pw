const API_URL = process.env.WARDEN_API_URL ?? 'https://api.agent.pw'

export interface CatalogService {
  slug: string
  allowedHosts: string
  displayName: string | null
  description: string | null
  docsUrl: string | null
  authSchemes: string | null
  oauthClientId: string | null
  credentialCount: number
}

export interface ServiceDetail {
  slug: string
  displayName: string | null
  description: string | null
  allowedHosts: string
  docsUrl: string | null
  authSchemes: string | null
  hasOAuth: boolean
}

/** Parse the first hostname from the allowedHosts JSON array. */
export function firstHost(allowedHosts: string) {
  try {
    const hosts: string[] = JSON.parse(allowedHosts)
    return hosts[0]
  } catch {
    return undefined
  }
}

export async function fetchCatalog() {
  try {
    const res = await fetch(`${API_URL}/api/catalog`, {
      next: { revalidate: 60 },
    })
    if (!res.ok) return []
    const data = await res.json()
    return data.services as CatalogService[]
  } catch {
    return []
  }
}

export async function fetchService(slug: string) {
  try {
    const res = await fetch(`${API_URL}/api/catalog/${encodeURIComponent(slug)}`, {
      next: { revalidate: 60 },
    })
    if (!res.ok) return null
    return (await res.json()) as ServiceDetail
  } catch {
    return null
  }
}

export function getApiUrl() {
  return process.env.NEXT_PUBLIC_WARDEN_API_URL ?? API_URL
}
