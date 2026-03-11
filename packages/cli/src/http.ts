import AgentPw from '@agent.pw/sdk'
import { resolve } from './resolve'

let _client: AgentPw | null = null

export interface PaginatedResponse<T> {
  data: T[]
  hasMore: boolean
  nextCursor: string | null
}

/** Get an authenticated AgentPw SDK client, resolved from env/config/session. */
export async function getClient() {
  if (_client) return _client
  const { url, token } = await resolve()
  _client = new AgentPw({ baseURL: url, apiKey: token })
  return _client
}

export async function request(path: string, init: RequestInit = {}) {
  const { url, token } = await resolve()
  const headers = new Headers(init.headers)
  if (!headers.has('Proxy-Authorization')) {
    headers.set('Proxy-Authorization', `Bearer ${token}`)
  }
  return fetch(`${url.replace(/\/$/, '')}${path}`, {
    ...init,
    headers,
  })
}

export async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await request(path, init)
  if (!res.ok) {
    const body = await res.text()
    const error = new Error(body || `${res.status} ${res.statusText}`) as Error & { status?: number }
    error.status = res.status
    throw error
  }
  return res.json() as Promise<T>
}

export async function requestPage<T>(path: string, init: RequestInit = {}) {
  const url = new URL(path, 'https://agent.pw')
  if (!url.searchParams.has('limit')) {
    url.searchParams.set('limit', '100')
  }
  return requestJson<PaginatedResponse<T>>(`${url.pathname}${url.search}`, init)
}

export async function requestAllPages<T>(path: string, init: RequestInit = {}) {
  const allItems: T[] = []
  let cursor: string | null = null

  do {
    const url = new URL(path, 'https://agent.pw')
    if (cursor) {
      url.searchParams.set('cursor', cursor)
    }

    const page = await requestPage<T>(`${url.pathname}${url.search}`, init)
    allItems.push(...page.data)
    cursor = page.nextCursor
  } while (cursor)

  return allItems
}
