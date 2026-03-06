import AgentPw from '@agent.pw/sdk'
import { resolve } from './resolve'

let _client: AgentPw | null = null

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
  if (!headers.has('agentpw-token') && !headers.has('Authorization')) {
    headers.set('agentpw-token', token)
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
