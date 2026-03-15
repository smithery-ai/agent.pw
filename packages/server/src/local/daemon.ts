import { spawn, type ChildProcess } from 'node:child_process'
import { openSync } from 'node:fs'
import {
  buildLocalBaseUrl,
  ensureLocalAgentPwDirs,
  isProcessAlive,
  type LocalAgentPwPaths,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
} from './config'
import { getLocalServerStatus, probeLocalServer, stopLocalServer } from './runtime'

export interface LocalDaemonRunner {
  command: string
  args: string[]
  cwd?: string
}

async function waitForDaemonStartup(
  child: ChildProcess,
  baseUrl: string,
  paths: LocalAgentPwPaths,
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
      return localPid
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for agent.pw at ${baseUrl}. Check ${paths.logFile}.`)
}

export async function ensureLocalServerDaemon(
  runner: LocalDaemonRunner,
  paths = localAgentPwPaths(),
) {
  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('agent.pw is not initialized. Run `npx agent.pw init` first.')
  }

  const baseUrl = buildLocalBaseUrl(config.port)
  const status = getLocalServerStatus(paths)

  if (await probeLocalServer(baseUrl)) {
    return {
      started: false,
      baseUrl,
      pid: status.pid,
      logFile: paths.logFile,
    }
  }

  if (status.running) {
    stopLocalServer(paths)
  }

  ensureLocalAgentPwDirs(paths)

  const logFd = openSync(paths.logFile, 'a')
  const child = spawn(runner.command, runner.args, {
    cwd: runner.cwd,
    detached: true,
    stdio: ['ignore', logFd, logFd],
    env: {
      ...process.env,
      AGENTPW_HOME: paths.homeDir,
    },
  })

  child.unref()
  const pid = await waitForDaemonStartup(child, baseUrl, paths)

  return {
    started: true,
    baseUrl,
    pid,
    logFile: paths.logFile,
  }
}
