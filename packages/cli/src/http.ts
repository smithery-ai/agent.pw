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
