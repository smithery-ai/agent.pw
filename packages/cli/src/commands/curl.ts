import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline/promises'
import { parseAgentPwChallenge } from '../auth-challenge'
import { openBrowser as launchBrowser } from '../local/onboarding'
import { resolveOptional } from '../resolve'

type CurlRunResult = {
  exitCode: number
  headers: Headers
  stdout: Buffer
  stderr: Buffer
}

export async function curl(args: string[]) {
  if (args.length === 0) {
    console.error('Usage: agent.pw curl <url> [curl-args...]')
    process.exit(1)
  }

  const resolved = await resolveOptional()
  if (!resolved) {
    console.error('No agent.pw instance is configured.')
    console.error('Run `npx agent.pw start` to create a local instance, or set AGENT_PW_HOST and AGENT_PW_TOKEN.')
    process.exit(1)
  }

  const proxyBase = resolved.url
  const token = resolved.token
  const { curlArgs, hostname } = buildProxyCurlArgs(args, proxyBase, token)

  const first = await runCurl(curlArgs)
  const challenge = parseAgentPwChallenge(first.headers.get('www-authenticate'))
  if (challenge) {
    const opened = await handleAuthChallenge(challenge, hostname)
    if (opened) {
      const retried = await runCurl(curlArgs)
      writeCapturedOutput(retried)
      process.exit(retried.exitCode)
    }
  }

  writeCapturedOutput(first)
  process.exit(first.exitCode)
}

function buildProxyCurlArgs(args: string[], proxyBase: string, token: string) {
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

  const target = args[urlIndex]
  if (!target) {
    throw new Error('No URL found in arguments.')
  }

  const targetUrl = new URL(target)
  const hostname = targetUrl.hostname
  const path = targetUrl.pathname + targetUrl.search
  const proxyUrl = `${proxyBase}/proxy/${hostname}${path}`

  const curlArgs = [...args]
  curlArgs[urlIndex] = proxyUrl
  curlArgs.push('-H', `Proxy-Authorization: Bearer ${token}`)

  return { curlArgs, hostname }
}

async function runCurl(args: string[]): Promise<CurlRunResult> {
  const tempDir = await mkdtemp(join(tmpdir(), 'agentpw-curl-'))
  const headersPath = join(tempDir, 'headers.txt')

  try {
    const { exitCode, stdout, stderr } = await spawnCurl([...args, '--dump-header', headersPath])
    const headers = parseHeaderDump(await safeRead(headersPath))
    return { exitCode, headers, stdout, stderr }
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
}

function spawnCurl(args: string[]) {
  return new Promise<{ exitCode: number; stdout: Buffer; stderr: Buffer }>((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['inherit', 'pipe', 'pipe'] })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []

    child.stdout.on('data', chunk => stdout.push(Buffer.from(chunk)))
    child.stderr.on('data', chunk => stderr.push(Buffer.from(chunk)))
    child.on('error', reject)
    child.on('close', code => {
      resolve({
        exitCode: code ?? 0,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      })
    })
  })
}

function parseHeaderDump(dump: string) {
  const headers = new Headers()
  const blocks = dump
    .split(/\r?\n\r?\n/)
    .map(block => block.trim())
    .filter(Boolean)
  const last = blocks.at(-1)
  if (!last) return headers

  for (const line of last.split(/\r?\n/).slice(1)) {
    const index = line.indexOf(':')
    if (index === -1) continue
    headers.append(line.slice(0, index).trim(), line.slice(index + 1).trim())
  }
  return headers
}

async function safeRead(path: string) {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return ''
  }
}

async function handleAuthChallenge(
  challenge: NonNullable<ReturnType<typeof parseAgentPwChallenge>>,
  hostname: string,
) {
  if (!challenge.authorizationUri) {
    const target = challenge.profile ?? challenge.targetHost ?? hostname
    console.error(`Authentication is required for ${target}.`)
    console.error(`Run \`agent.pw cred add ${target}\` or complete the flow in the browser.`)
    return false
  }

  console.error(`Authentication is required for ${challenge.targetHost ?? hostname}.`)
  console.error(`Opening browser: ${challenge.authorizationUri}`)
  await openBrowser(challenge.authorizationUri)

  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  })
  try {
    await rl.question('Finish the browser flow, then press Enter to retry this request.')
  } finally {
    rl.close()
  }

  return true
}

async function openBrowser(url: string) {
  launchBrowser(url)
}

function writeCapturedOutput(result: CurlRunResult) {
  if (result.stdout.length > 0) process.stdout.write(result.stdout)
  if (result.stderr.length > 0) process.stderr.write(result.stderr)
}
