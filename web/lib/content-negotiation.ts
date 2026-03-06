const AGENT_USER_AGENTS = [
  'curl/',
  'wget/',
  'httpie/',
  'python-requests/',
  'node-fetch/',
  'undici/',
  'axios/',
  'got/',
]

export function isAgentRequest(headers: Headers) {
  const accept = headers.get('accept') ?? ''
  if (accept.includes('text/markdown') || accept.includes('text/plain')) {
    return true
  }

  // If explicitly requesting HTML, not an agent
  if (accept.includes('text/html')) {
    return false
  }

  const ua = (headers.get('user-agent') ?? '').toLowerCase()
  return AGENT_USER_AGENTS.some((agent) => ua.includes(agent))
}
