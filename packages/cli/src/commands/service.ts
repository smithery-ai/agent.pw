import { readFileSync } from 'node:fs'
import { getClient } from '../http'
import type { ServiceCreateParams } from '@agent.pw/sdk/resources/services'

export async function listServices() {
  const client = await getClient()
  const services = await client.services.list()

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
  const client = await getClient()
  try {
    const service = await client.services.get(slug)
    console.log(JSON.stringify(service, null, 2))
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Service '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

export async function addService(slug: string, hosts: string[], filePath?: string) {
  let body: ServiceCreateParams

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

  const client = await getClient()
  await client.services.create(slug, body)
  console.log(`Service '${slug}' registered.`)
}

export async function removeService(slug: string) {
  const client = await getClient()
  try {
    await client.services.delete(slug)
    console.log(`Service '${slug}' removed.`)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Service '${slug}' not found.`)
      process.exit(1)
    }
    throw e
  }
}

function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 404
}
