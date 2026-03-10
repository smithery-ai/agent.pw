import { getClient, requestJson } from '../http'
import { output } from '../output'

interface RestrictConstraint {
  services?: string | string[]
  methods?: string | string[]
  paths?: string | string[]
  ttl?: string
}

function collectFlagValues(args: string[], names: string[]) {
  const values: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (names.includes(args[i]) && args[i + 1]) {
      values.push(args[i + 1])
      i++
    }
  }
  return values
}

export async function restrictTokenCmd(args: string[]) {
  const services = collectFlagValues(args, ['--service', '--host'])
  const methods = collectFlagValues(args, ['--method'])
  const paths = collectFlagValues(args, ['--path'])
  const ttlIndex = args.indexOf('--ttl')
  const ttl = ttlIndex !== -1 ? args[ttlIndex + 1] : undefined

  const constraint: RestrictConstraint = {}
  if (services.length > 0) constraint.services = services.length === 1 ? services[0] : services
  if (methods.length > 0) constraint.methods = methods.length === 1 ? methods[0].toUpperCase() : methods.map(m => m.toUpperCase())
  if (paths.length > 0) constraint.paths = paths.length === 1 ? paths[0] : paths
  if (ttl) constraint.ttl = ttl

  if (Object.keys(constraint).length === 0) {
    console.error('Usage: agent.pw token restrict [--service <host>] [--method <verb>] [--path </prefix>] [--ttl <1h>]')
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
