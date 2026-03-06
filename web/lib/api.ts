const API_URL = process.env.WARDEN_API_URL ?? 'https://agent.pw'

export interface CatalogService {
  service: string
  baseUrl: string
  displayName: string | null
  description: string | null
  docsUrl: string | null
  authSchemes: string | null
  oauthClientId: string | null
  credentialCount: number
}

export interface ServiceDetail {
  service: string
  displayName: string | null
  description: string | null
  baseUrl: string
  docsUrl: string | null
  authSchemes: string | null
  hasOAuth: boolean
}

export async function fetchCatalog() {
  const res = await fetch(`${API_URL}/api/catalog`, {
    next: { revalidate: 60 },
  })
  if (!res.ok) return []
  const data = await res.json()
  return data.services as CatalogService[]
}

export async function fetchService(slug: string) {
  const res = await fetch(`${API_URL}/api/catalog/${encodeURIComponent(slug)}`, {
    next: { revalidate: 60 },
  })
  if (!res.ok) return null
  return (await res.json()) as ServiceDetail
}

export function getApiUrl() {
  return process.env.NEXT_PUBLIC_WARDEN_API_URL ?? API_URL
}
