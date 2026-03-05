import { createServer } from 'node:http'
import { writeManagedSession } from '../config'

const DEFAULT_HOST = 'https://agent.pw'

export async function login(host?: string) {
  const targetHost = host ?? DEFAULT_HOST

  const { token, cleanup } = await browserLogin(targetHost)

  // Validate the token by calling /services
  const res = await fetch(`${targetHost}/services`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  if (!res.ok) {
    cleanup()
    console.error(`Authentication failed (${res.status}). Check your token.`)
    process.exit(1)
  }

  writeManagedSession({ host: targetHost, token })
  cleanup()
  console.log(`Logged in to ${targetHost}`)
}

async function browserLogin(targetHost: string) {
  const { promise, resolve, reject } = Promise.withResolvers<string>()

  const server = createServer((req, res) => {
    const url = new URL(req.url!, `http://localhost`)
    const token = url.searchParams.get('token')

    if (token) {
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end('<html><body><h2>Login successful!</h2><p>You can close this tab.</p></body></html>')
      resolve(token)
    } else {
      res.writeHead(400, { 'Content-Type': 'text/plain' })
      res.end('Missing token')
      reject(new Error('Callback received without token'))
    }
  })

  // Listen on a random port
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  const port = (server.address() as { port: number }).port
  const callbackUrl = `http://localhost:${port}/callback`
  const loginUrl = `${targetHost}/auth/login?return_to=${encodeURIComponent(`/auth/cli-token?callback_url=${encodeURIComponent(callbackUrl)}`)}`

  console.log(`Opening browser to log in...`)
  console.log(`If the browser doesn't open, visit: ${loginUrl}`)

  // Open the browser
  const { exec } = await import('node:child_process')
  const open = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open'
  exec(`${open} "${loginUrl}"`)

  const timeout = setTimeout(() => {
    reject(new Error('Login timed out after 5 minutes'))
  }, 5 * 60 * 1000)

  const token = await promise
  clearTimeout(timeout)

  return {
    token,
    cleanup: () => server.close(),
  }
}
