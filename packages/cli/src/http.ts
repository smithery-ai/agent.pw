import AgentPw from '@agent.pw/sdk'
import { resolve } from './resolve'
import { HttpStatusError } from './type-utils'

let _client: AgentPw | null = null

export interface PaginatedResponse<T> {
  data: T[]
  hasMore: boolean
  nextCursor: string | null
}

/** Get an authenticated AgentPw SDK client, resolved from env or local config. */
export async function getClient() {
  if (_client) return _client
  const { url, token } = await resolve()
  _client = new AgentPw({ baseURL: url, apiKey: token })
  return _client
}

export async function request(path: string, init: RequestInit = {}) {
  const { url, token } = await resolve()
  const headers = new Headers(init.headers)
  if (!headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
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
    throw new HttpStatusError(body || `${res.status} ${res.statusText}`, res.status)
  }
  return res.json()
}

export async function pageToPaginatedResponse<T>(pagePromise: Promise<{
  data: T[]
  hasMore: boolean
  nextCursor?: string | null
}>) {
  const page = await pagePromise
  return {
    data: page.data,
    hasMore: page.hasMore,
    nextCursor: page.nextCursor ?? null,
  } satisfies PaginatedResponse<T>
}

export async function collectAllPages<T>(pages: AsyncIterable<T>) {
  const allItems: T[] = []
  for await (const item of pages) {
    allItems.push(item)
  }
  return allItems
}
