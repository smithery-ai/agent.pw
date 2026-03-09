export type AgentPwChallenge = {
  scheme: 'AgentPW'
  authorizationUri?: string
  profile?: string
  targetHost?: string
}

export function parseAgentPwChallenge(headerValue: string | null | undefined): AgentPwChallenge | null {
  if (!headerValue) return null
  const match = /AgentPW\s+(.+)/i.exec(headerValue)
  if (!match) return null

  const params: Record<string, string> = {}
  const pairs = match[1]?.matchAll(/([a-z_]+)="([^"]*)"/gi) ?? []
  for (const pair of pairs) {
    const key = pair[1]?.toLowerCase()
    const value = pair[2]
    if (key && value !== undefined) params[key] = value
  }

  return {
    scheme: 'AgentPW',
    authorizationUri: params.authorization_uri,
    profile: params.profile,
    targetHost: params.target_host,
  }
}
