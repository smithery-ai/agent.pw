import { createInterface } from 'node:readline'
import { getClient } from '../http'

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
  const client = await getClient()
  const creds = await client.credentials.list()

  if (creds.length === 0) {
    console.log('No credentials stored. Add one with `agent.pw cred add <slug>`.')
    return
  }

  console.log(`${'SLUG'.padEnd(20)}${'LABEL'.padEnd(15)}ADDED`)
  for (const cr of creds) {
    const added = cr.createdAt ? relativeTime(cr.createdAt) : ''
    console.log(`${cr.slug.padEnd(20)}${cr.label.padEnd(15)}${added}`)
  }
}

export async function addCred(slug: string, value?: string) {
  const client = await getClient()

  // Ensure the service exists
  try {
    await client.services.get(slug)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`Service '${slug}' not found. Register it first with: agent.pw service add ${slug} --host <hostname>`)
      process.exit(1)
    }
    throw e
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

  await client.credentials.store(slug, { token: value })
  console.log('Stored.')
}

export async function removeCred(slug: string) {
  const client = await getClient()
  try {
    await client.credentials.delete(slug)
    console.log(`Removed credential for ${slug}.`)
  } catch (e: unknown) {
    if (isNotFound(e)) {
      console.error(`No credential found for '${slug}'.`)
      process.exit(1)
    }
    throw e
  }
}

function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && 'status' in e && (e as { status: number }).status === 404
}
