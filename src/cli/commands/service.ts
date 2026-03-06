import { readFileSync } from 'node:fs'
import { api } from '../http'

export async function listServices() {
  const res = await api('/services')
  if (!res.ok) {
    console.error(`Failed to list services (${res.status})`)
    process.exit(1)
  }

  const services = (await res.json()) as Array<{
    slug: string
    allowedHosts: string[]
    description?: string
  }>

  if (services.length === 0) {
    console.log('No services registered.')
    return
  }

  console.log(`${'SLUG'.padEnd(20)}${'HOSTS'.padEnd(40)}DESCRIPTION`)
  for (const s of services) {
    const hosts = s.allowedHosts.join(', ')
    const desc = s.description ? s.description.slice(0, 40) : ''
    console.log(`${s.slug.padEnd(20)}${hosts.padEnd(40)}${desc}`)
  }
}

export async function getServiceCmd(slug: string) {
  const res = await api(`/services/${slug}`)
  if (res.status === 404) {
    console.error(`Service '${slug}' not found.`)
    process.exit(1)
  }
  if (!res.ok) {
    console.error(`Failed to get service (${res.status})`)
    process.exit(1)
  }

  const body = await res.json()
  console.log(JSON.stringify(body, null, 2))
}

export async function addService(slug: string, hosts: string[], filePath?: string) {
  let body: Record<string, unknown>

  if (filePath) {
    const content = readFileSync(filePath, 'utf-8')
    body = JSON.parse(content)
    if (!body.allowedHosts && hosts.length > 0) {
      body.allowedHosts = hosts
    }
  } else {
    if (hosts.length === 0) {
      console.error('At least one --host is required.')
      process.exit(1)
    }
    body = { allowedHosts: hosts }
  }

  const res = await api(`/services/${slug}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to add service: ${err.error ?? res.statusText}`)
    process.exit(1)
  }

  console.log(`Service '${slug}' registered.`)
}

export async function removeService(slug: string) {
  const res = await api(`/services/${slug}`, { method: 'DELETE' })
  if (res.status === 404) {
    console.error(`Service '${slug}' not found.`)
    process.exit(1)
  }
  if (!res.ok) {
    console.error(`Failed to remove service (${res.status})`)
    process.exit(1)
  }

  console.log(`Service '${slug}' removed.`)
}
