import { existsSync, readFileSync } from 'node:fs'
import { readConfig, getPidFile, readManagedSession } from './config'

export interface ResolvedEndpoint {
  url: string
  token: string
}

export const DEFAULT_MANAGED_HOST = 'https://api.agent.pw'

/**
 * Resolve the agent.pw endpoint. Priority:
 * 1. AGENT_PW_HOST + AGENT_PW_TOKEN env vars
 * 2. Local config + running server
 * 3. Managed session (~/.agent.pw/session.json)
 */
export async function resolveOptional(): Promise<ResolvedEndpoint | null> {
  // 1. Environment variables
  const envHost = process.env.AGENT_PW_HOST
  const envToken = process.env.AGENT_PW_TOKEN
  if (envHost && envToken) {
    return { url: envHost.replace(/\/$/, ''), token: envToken }
  }

  // 2. Local instance
  const config = readConfig()
  if (config) {
    const pidFile = getPidFile()
    if (existsSync(pidFile)) {
      const pid = parseInt(readFileSync(pidFile, 'utf-8').trim(), 10)
      try {
        process.kill(pid, 0)
        return {
          url: `http://local.agent.pw:${config.port}`,
          token: config.masterToken,
        }
      } catch {
        // Process not running, fall through to managed
      }
    }
  }

  // 3. Managed session
  const session = readManagedSession()
  if (session) {
    return { url: session.host.replace(/\/$/, ''), token: session.token }
  }

  // 4. Local config exists but server not running — use it anyway
  if (config) {
    return {
      url: `http://local.agent.pw:${config.port}`,
      token: config.masterToken,
    }
  }

  return null
}

export async function resolve(): Promise<ResolvedEndpoint> {
  const resolved = await resolveOptional()
  if (resolved) return resolved

  console.error('No agent.pw instance available.')
  console.error(`  Run \`agent.pw login\` to connect to ${DEFAULT_MANAGED_HOST}`)
  console.error('  Or set AGENT_PW_HOST and AGENT_PW_TOKEN environment variables')
  process.exit(1)
}
