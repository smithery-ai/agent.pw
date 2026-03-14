import { buildLocalBaseUrl } from '../../server/src/local/config'
import { readConfig, readTokenStack } from './config'

interface ResolvedEndpoint {
  url: string
  token: string
}

/**
 * Resolve the agent.pw endpoint. Priority:
 * 1. AGENT_PW_HOST + AGENT_PW_TOKEN env vars
 * 2. Local config + local daemon
 */
export async function resolveOptional(): Promise<ResolvedEndpoint | null> {
  const envHost = process.env.AGENT_PW_HOST?.trim()
  const envToken = process.env.AGENT_PW_TOKEN?.trim()
  if (envHost && envToken) {
    return { url: envHost.replace(/\/$/, ''), token: envToken }
  }

  const config = readConfig()
  if (!config) {
    return null
  }

  return {
    url: buildLocalBaseUrl(config.port),
    token: config.masterToken,
  }
}

export async function resolve(): Promise<ResolvedEndpoint> {
  const resolved = await resolveOptional()
  if (!resolved) {
    console.error('No agent.pw instance is configured.')
    console.error('  Run `npx agent.pw init` to create and start a local instance')
    console.error('  Or set AGENT_PW_HOST and AGENT_PW_TOKEN for a remote self-hosted deployment')
    process.exit(1)
  }

  const stack = readTokenStack()
  if (stack.length > 0) {
    resolved.token = stack[stack.length - 1]
  }

  return resolved
}
