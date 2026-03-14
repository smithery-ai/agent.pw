import { createHash } from 'node:crypto'
import { existsSync, openSync } from 'node:fs'
import { chmod, mkdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { spawn } from 'node:child_process'
import {
  buildLocalBaseUrl,
  clearStaleLocalPid,
  ensureLocalAgentPwDirs,
  isProcessAlive,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
  removeLocalPid,
  writeExecutableFile,
} from '../../../server/src/local/config'
import { SERVER_BINARY_MANIFEST } from './server-binary-manifest.generated'

export interface EnsureServerBinaryResult {
  binaryPath: string
  source: 'env' | 'cache' | 'download'
}

interface LocalServerStatus {
  configured: boolean
  running: boolean
  pid: number | null
  baseUrl: string | null
}

function binaryKey() {
  return `${process.platform}-${process.arch}`
}

function resolveBinaryAsset() {
  const key = binaryKey()
  const asset = SERVER_BINARY_MANIFEST[key]

  if (!asset) {
    throw new Error(
      `No local agent.pw server binary is published for ${key}. Set AGENTPW_SERVER_BINARY_PATH to a compatible executable.`,
    )
  }

  return asset
}

function sha256Hex(contents: Uint8Array) {
  return createHash('sha256').update(contents).digest('hex')
}

function binaryCachePath(paths = localAgentPwPaths()) {
  const asset = resolveBinaryAsset()
  return join(paths.serverRuntimeDir, asset.fileName)
}

async function verifyExistingBinary(filePath: string, sha256: string) {
  if (!existsSync(filePath)) {
    return false
  }

  const bytes = await readFile(filePath)
  return sha256Hex(bytes) === sha256
}

async function downloadBinary(
  url: string,
  expectedSha256: string,
  outputPath: string,
) {
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`Failed to download local server binary from ${url} (${res.status})`)
  }

  const bytes = new Uint8Array(await res.arrayBuffer())
  const actualSha256 = sha256Hex(bytes)
  if (actualSha256 !== expectedSha256) {
    throw new Error(
      `Downloaded local server binary checksum mismatch. Expected ${expectedSha256}, got ${actualSha256}.`,
    )
  }

  writeExecutableFile(outputPath, bytes)
}

export async function ensureLocalServerBinary(
  paths = localAgentPwPaths(),
): Promise<EnsureServerBinaryResult> {
  const overridePath = process.env.AGENTPW_SERVER_BINARY_PATH?.trim()
  if (overridePath) {
    if (!existsSync(overridePath)) {
      throw new Error(`AGENTPW_SERVER_BINARY_PATH does not exist: ${overridePath}`)
    }

    return { binaryPath: overridePath, source: 'env' }
  }

  ensureLocalAgentPwDirs(paths)

  const asset = resolveBinaryAsset()
  if (!/^[a-f0-9]{64}$/i.test(asset.sha256)) {
    throw new Error(
      `The published CLI does not have a local server checksum for ${binaryKey()} yet. Set AGENTPW_SERVER_BINARY_PATH to a compatible executable.`,
    )
  }

  const outputPath = binaryCachePath(paths)
  if (await verifyExistingBinary(outputPath, asset.sha256)) {
    return { binaryPath: outputPath, source: 'cache' }
  }

  await mkdir(dirname(outputPath), { recursive: true })
  await downloadBinary(asset.url, asset.sha256, outputPath)
  await chmod(outputPath, 0o755)
  return { binaryPath: outputPath, source: 'download' }
}

export function getLocalServerStatus(paths = localAgentPwPaths()): LocalServerStatus {
  const config = readLocalConfig(paths)
  clearStaleLocalPid(paths)
  const pid = readLocalPid(paths)

  return {
    configured: config !== null,
    running: pid !== null && isProcessAlive(pid),
    pid,
    baseUrl: config ? buildLocalBaseUrl(config.port) : null,
  }
}

export async function probeLocalServer(baseUrl: string, timeoutMs = 1_000) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/`, {
      signal: controller.signal,
    })
    return res.ok
  } catch {
    return false
  } finally {
    clearTimeout(timeout)
  }
}

async function waitForLocalServer(baseUrl: string, timeoutMs = 15_000, intervalMs = 250) {
  const startedAt = Date.now()

  while (Date.now() - startedAt < timeoutMs) {
    if (await probeLocalServer(baseUrl)) {
      return
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for agent.pw at ${baseUrl}`)
}

export async function startLocalServerDaemon(
  binaryPath: string,
  paths = localAgentPwPaths(),
) {
  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('agent.pw is not initialized. Run `npx agent.pw init` first.')
  }

  const status = getLocalServerStatus(paths)
  const baseUrl = buildLocalBaseUrl(config.port)

  if (status.running && (await probeLocalServer(baseUrl, 1_000))) {
    return {
      started: false,
      baseUrl,
      pid: status.pid,
      logFile: paths.logFile,
    }
  }

  if (status.running) {
    stopLocalServerDaemon(paths)
  }

  ensureLocalAgentPwDirs(paths)

  const logFd = openSync(paths.logFile, 'a')
  const child = spawn(binaryPath, ['serve'], {
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: {
      ...process.env,
      AGENTPW_HOME: paths.homeDir,
    },
  })

  child.unref()
  await waitForLocalServer(baseUrl)

  return {
    started: true,
    baseUrl,
    pid: child.pid ?? null,
    logFile: paths.logFile,
  }
}

export async function runLocalServerBinaryCommand(
  binaryPath: string,
  args: string[],
  paths = localAgentPwPaths(),
) {
  const child = spawn(binaryPath, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      AGENTPW_HOME: paths.homeDir,
    },
  })

  let stdout = ''
  let stderr = ''

  child.stdout.on('data', chunk => {
    stdout += chunk
  })
  child.stderr.on('data', chunk => {
    stderr += chunk
  })

  const exitCode = await new Promise<number>((resolve, reject) => {
    child.on('error', reject)
    child.on('exit', code => resolve(code ?? 1))
  })

  if (exitCode !== 0) {
    throw new Error(stderr.trim() || stdout.trim() || `${binaryPath} ${args.join(' ')} exited with code ${exitCode}`)
  }

  return stdout.trim()
}

export function stopLocalServerDaemon(paths = localAgentPwPaths()) {
  clearStaleLocalPid(paths)
  const pid = readLocalPid(paths)

  if (!pid) {
    return false
  }

  process.kill(pid, 'SIGTERM')
  removeLocalPid(paths)
  return true
}

export function describeLocalServer(paths = localAgentPwPaths()) {
  const status = getLocalServerStatus(paths)

  return {
    ...status,
    logFile: paths.logFile,
    configFile: paths.configFile,
  }
}

export async function readLocalServerLogs(
  paths = localAgentPwPaths(),
  tail = 200,
) {
  if (!existsSync(paths.logFile)) {
    return null
  }

  const contents = await readFile(paths.logFile, 'utf8')
  const lines = contents.split(/\r?\n/)
  return lines.slice(Math.max(0, lines.length - tail)).join('\n').trim()
}

export function buildVaultLaunchUrl(
  baseUrl: string,
  bootstrapToken: string,
  vaultUrl = process.env.AGENTPW_VAULT_URL?.trim() || 'https://agent.pw/vault',
) {
  const url = new URL(vaultUrl)
  url.searchParams.set('url', baseUrl)
  url.hash = `agentpw_token=${encodeURIComponent(bootstrapToken)}`
  return url.toString()
}

export function printServerSummary(paths = localAgentPwPaths()) {
  const config = readLocalConfig(paths)
  const status = describeLocalServer(paths)

  if (!config) {
    console.log('agent.pw is not initialized.')
    console.log('Run `npx agent.pw init` to create a local instance.')
    return
  }

  console.log(`Config: ${paths.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    ${status.baseUrl}`)
  console.log(`Log:    ${paths.logFile}`)
  console.log(status.running ? `State:  running (PID ${status.pid})` : 'State:  stopped')
}
