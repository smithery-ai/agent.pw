import { api } from '../http'

export async function restrictTokenCmd(args: string[]) {
  const token = args[0]
  if (!token) {
    console.error('Usage: agent.pw token restrict <token> [--service <host>] [--method <m>] [--ttl <duration>]')
    process.exit(1)
  }

  const constraints: Record<string, unknown> = {}

  const serviceIdx = args.indexOf('--service')
  if (serviceIdx !== -1) constraints.services = args[serviceIdx + 1]

  const methodIdx = args.indexOf('--method')
  if (methodIdx !== -1) constraints.methods = args[methodIdx + 1]

  const ttlIdx = args.indexOf('--ttl')
  if (ttlIdx !== -1) constraints.ttl = args[ttlIdx + 1]

  const res = await api('/tokens/restrict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, constraints: [constraints] }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to restrict token: ${body.error ?? res.statusText}`)
    process.exit(1)
  }

  const { token: restricted } = await res.json() as { token: string }
  console.log(restricted)
}

export async function revokeTokenCmd(args: string[]) {
  const token = args[0]
  if (!token) {
    console.error('Usage: agent.pw token revoke <token>')
    process.exit(1)
  }

  const res = await api('/tokens/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to revoke token: ${body.error ?? res.statusText}`)
    process.exit(1)
  }

  console.log('Token revoked.')
}
