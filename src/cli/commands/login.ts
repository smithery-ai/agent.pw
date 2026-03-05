import { createInterface } from 'node:readline'
import { writeManagedSession } from '../config'

const DEFAULT_HOST = 'https://agent.pw'

export async function login(host?: string) {
  const targetHost = host ?? DEFAULT_HOST

  const rl = createInterface({ input: process.stdin, output: process.stderr })
  const token = await new Promise<string>(resolve => {
    rl.question('Paste your agent.pw token: ', answer => {
      rl.close()
      resolve(answer.trim())
    })
  })

  if (!token) {
    console.error('No token provided.')
    process.exit(1)
  }

  // Validate the token by calling /services
  const res = await fetch(`${targetHost}/services`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  if (!res.ok) {
    console.error(`Authentication failed (${res.status}). Check your token.`)
    process.exit(1)
  }

  writeManagedSession({ host: targetHost, token })
  console.log(`Logged in to ${targetHost}`)
}
