import { existsSync, openSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { spawn, type ChildProcess } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  buildLocalBaseUrl,
  clearStaleLocalPid,
  ensureLocalAgentPwDirs,
  isProcessAlive,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
  removeLocalPid,
} from '../../../server/src/local/config'

export interface LocalDaemonRunner {
  command: string
  args: string[]
  cwd?: string
  displayPath: string
  source: 'bundle' | 'source'
}

interface LocalServerStatus {
  configured: boolean
  running: boolean
  pid: number | null
  baseUrl: string | null
}

function findFileUpward(startDir: string, relativePath: string) {
  let currentDir = startDir

  while (true) {
    const candidate = join(currentDir, relativePath)
    if (existsSync(candidate)) {
      return candidate
    }

    const parentDir = dirname(currentDir)
    if (parentDir === currentDir) {
      return null
    }
    currentDir = parentDir
  }
}

function commandErrorMessage() {
  return [
    'Unable to find the local agent.pw daemon.',
    'Reinstall `agent.pw` to restore `dist/local-daemon.js`, or run from a source checkout with dependencies installed.',
  ].join(' ')
}

export function resolveLocalDaemonRunner(): LocalDaemonRunner {
  return resolveLocalDaemonRunnerFrom(fileURLToPath(import.meta.url))
}

export function resolveLocalDaemonRunnerFrom(
  moduleFilePath: string,
  cwd = process.cwd(),
): LocalDaemonRunner {
  const currentModuleDir = dirname(moduleFilePath)
  const bundledDaemon = join(currentModuleDir, 'local-daemon.js')
  if (existsSync(bundledDaemon)) {
    return {
      command: process.execPath,
      args: [bundledDaemon],
      displayPath: bundledDaemon,
      source: 'bundle',
    }
  }

  const sourceDaemon = join(currentModuleDir, '..', 'local-daemon.ts')
  const tsxBinary = (
    findFileUpward(cwd, join('node_modules', '.bin', process.platform === 'win32' ? 'tsx.cmd' : 'tsx'))
    ?? findFileUpward(currentModuleDir, join('node_modules', '.bin', process.platform === 'win32' ? 'tsx.cmd' : 'tsx'))
  )
  if (existsSync(sourceDaemon) && tsxBinary) {
    return {
      command: process.execPath,
      args: ['--no-warnings=ExperimentalWarning', '--loader', 'tsx', sourceDaemon],
      cwd: dirname(dirname(dirname(dirname(sourceDaemon)))),
      displayPath: sourceDaemon,
      source: 'source',
    }
  }

  throw new Error(commandErrorMessage())
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

async function waitForDaemonStartup(
  child: ChildProcess,
  baseUrl: string,
  paths = localAgentPwPaths(),
  timeoutMs = 15_000,
  intervalMs = 250,
) {
  const startedAt = Date.now()
  let exitCode: number | null = null
  let spawnError: Error | null = null

  child.once('error', error => {
    spawnError = error
  })
  child.once('exit', code => {
    exitCode = code ?? 1
  })

  while (Date.now() - startedAt < timeoutMs) {
    if (spawnError) {
      throw spawnError
    }

    if (exitCode !== null) {
      throw new Error(`Local agent.pw daemon exited before startup. Check ${paths.logFile}.`)
    }

    const localPid = readLocalPid(paths)
    if (localPid && isProcessAlive(localPid) && (await probeLocalServer(baseUrl))) {
      return
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for agent.pw at ${baseUrl}. Check ${paths.logFile}.`)
}

export async function startLocalServerDaemon(
  runner: LocalDaemonRunner,
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
  const child = spawn(runner.command, [...runner.args, 'serve'], {
    cwd: runner.cwd,
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: {
      ...process.env,
      AGENTPW_HOME: paths.homeDir,
    },
  })

  child.unref()
  await waitForDaemonStartup(child, baseUrl, paths)

  return {
    started: true,
    baseUrl,
    pid: child.pid ?? null,
    logFile: paths.logFile,
  }
}

export async function runLocalServerDaemonCommand(
  runner: LocalDaemonRunner,
  args: string[],
  paths = localAgentPwPaths(),
) {
  const child = spawn(runner.command, [...runner.args, ...args], {
    cwd: runner.cwd,
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
    throw new Error(
      stderr.trim()
      || stdout.trim()
      || `${runner.displayPath} ${args.join(' ')} exited with code ${exitCode}`,
    )
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
