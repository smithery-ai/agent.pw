import { readFileSync } from 'node:fs'
import { api } from '../http'

export async function listServices() {
  const res = await api('/services')
  if (!res.ok) {
    console.error(`Failed to list services (${res.status})`)
    process.exit(1)
  }

  const services = (await res.json()) as Array<{
    service: string
    baseUrl: string
    description?: string
  }>

  if (services.length === 0) {
    console.log('No services registered.')
    return
  }

  console.log(`${'SERVICE'.padEnd(35)}${'BASE URL'.padEnd(35)}DESCRIPTION`)
  for (const s of services) {
    const desc = s.description ? s.description.slice(0, 40) : ''
    console.log(`${s.service.padEnd(35)}${s.baseUrl.padEnd(35)}${desc}`)
  }
}

export async function getServiceCmd(service: string) {
  const res = await api(`/services/${service}`)
  if (res.status === 404) {
    console.error(`Service '${service}' not found.`)
    process.exit(1)
  }
  if (!res.ok) {
    console.error(`Failed to get service (${res.status})`)
    process.exit(1)
  }

  const body = await res.json()
  console.log(JSON.stringify(body, null, 2))
}

export async function addService(service: string, filePath?: string) {
  let body: Record<string, unknown>

  if (filePath) {
    const content = readFileSync(filePath, 'utf-8')
    body = JSON.parse(content)
    if (!body.baseUrl) {
      body.baseUrl = `https://${service}`
    }
  } else {
    body = { baseUrl: `https://${service}` }
  }

  const res = await api(`/services/${service}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as Record<string, string>
    console.error(`Failed to add service: ${err.error ?? res.statusText}`)
    process.exit(1)
  }

  console.log(`Service '${service}' registered.`)
}

export async function removeService(service: string) {
  const res = await api(`/services/${service}`, { method: 'DELETE' })
  if (res.status === 404) {
    console.error(`Service '${service}' not found.`)
    process.exit(1)
  }
  if (!res.ok) {
    console.error(`Failed to remove service (${res.status})`)
    process.exit(1)
  }

  console.log(`Service '${service}' removed.`)
}
