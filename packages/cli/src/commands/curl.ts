import { spawn } from 'node:child_process'
import { resolve } from '../resolve'

export async function curl(args: string[]) {
  if (args.length === 0) {
    console.error('Usage: agent.pw curl <url> [curl-args...]')
    process.exit(1)
  }

  const { url: proxyBase, token } = await resolve()

  // Find the URL argument (first arg that looks like a URL or hostname path)
  let urlIndex = -1
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('http://') || args[i].startsWith('https://')) {
      urlIndex = i
      break
    }
  }

  if (urlIndex === -1) {
    console.error('No URL found in arguments. Usage: agent.pw curl <url> [curl-args...]')
    process.exit(1)
  }

  const targetUrl = new URL(args[urlIndex])
  const hostname = targetUrl.hostname
  const path = targetUrl.pathname + targetUrl.search

  // Rewrite URL through the proxy: /proxy/{hostname}/{path}
  const proxyUrl = `${proxyBase}/proxy/${hostname}${path}`
  const curlArgs = [...args]
  curlArgs[urlIndex] = proxyUrl

  // Inject the proxy auth header without taking over upstream Authorization.
  curlArgs.push('-H', `agentpw-token: ${token}`)

  // Spawn curl
  const child = spawn('curl', curlArgs, { stdio: 'inherit' })
  child.on('exit', (code) => process.exit(code ?? 0))
}
