import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  buildLocalBaseUrl,
  clearStaleLocalPid,
  isProcessAlive,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
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
