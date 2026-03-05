import { resolve } from './resolve'

/** Make an authenticated API call to the resolved agent.pw endpoint. */
export async function api(path: string, init: RequestInit = {}) {
  const { url, token } = await resolve()
  const fullUrl = `${url}${path}`
  return fetch(fullUrl, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...init.headers,
    },
  })
}
