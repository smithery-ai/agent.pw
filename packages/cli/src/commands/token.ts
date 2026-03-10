import { getClient, requestJson } from '../http'
import { output } from '../output'

interface RestrictOptions {
  services?: string[]
  methods?: string[]
  paths?: string[]
  ttl?: string
}

export async function restrictTokenCmd(opts: RestrictOptions) {
  const constraint: Record<string, unknown> = {}
  if (opts.services && opts.services.length > 0) {
    constraint.services = opts.services.length === 1 ? opts.services[0] : opts.services
  }
  if (opts.methods && opts.methods.length > 0) {
    const upper = opts.methods.map(m => m.toUpperCase())
    constraint.methods = upper.length === 1 ? upper[0] : upper
  }
  if (opts.paths && opts.paths.length > 0) {
    constraint.paths = opts.paths.length === 1 ? opts.paths[0] : opts.paths
  }
  if (opts.ttl) constraint.ttl = opts.ttl

  if (Object.keys(constraint).length === 0) {
    console.error('At least one constraint is required (--service, --method, --path, or --ttl).')
    process.exit(1)
  }

  const res = await requestJson<{ token: string }>('/tokens/restrict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ constraints: [constraint] }),
  })

  if (output(res)) return
  console.log(res.token)
}

export async function revokeTokenCmd() {
  const client = await getClient()
  await client.tokens.revoke({})
  console.log('Token revoked.')
}
