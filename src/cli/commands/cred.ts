import { createInterface } from 'node:readline'
import { api } from '../http'

function relativeTime(date: string) {
  const diff = Date.now() - new Date(date).getTime()
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export async function listCreds() {
  const res = await api('/credentials')
  if (!res.ok) {
    console.error(`Failed to list credentials (${res.status})`)
    process.exit(1)
  }

  const creds = (await res.json()) as Array<{
    service: string
    slug: string
    createdAt?: string
  }>

  if (creds.length === 0) {
    console.log('No credentials stored. Add one with `agent.pw cred add <service>`.')
    return
  }

  console.log(`${'SERVICE'.padEnd(30)}ADDED`)
  for (const cr of creds) {
    const added = cr.createdAt ? relativeTime(cr.createdAt) : ''
    console.log(`${cr.service.padEnd(30)}${added}`)
  }
}

export async function addCred(service: string, value?: string) {
  // Ensure the service exists
  const svcRes = await api(`/services/${service}`)
  if (svcRes.status === 404) {
    // Auto-register the service with defaults
    const putRes = await api(`/services/${service}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseUrl: `https://${service}` }),
    })
    if (!putRes.ok) {
      console.error(`Failed to register service '${service}' (${putRes.status})`)
      process.exit(1)
    }
  } else if (!svcRes.ok) {
    console.error(`Failed to check service '${service}' (${svcRes.status})`)
    process.exit(1)
  }

  // Prompt for value if not provided via --value
  if (!value) {
    const rl = createInterface({ input: process.stdin, output: process.stderr })
    value = await new Promise<string>(resolve => {
      rl.question('Paste your API key: ', answer => {
        rl.close()
        resolve(answer.trim())
      })
    })
    if (!value) {
      console.error('No value provided.')
      process.exit(1)
    }
  }

  const res = await api(`/credentials/${service}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: value }),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to store credential: ${body.error ?? res.statusText}`)
    process.exit(1)
  }

  console.log('Stored.')
}
