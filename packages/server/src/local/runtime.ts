import {
  buildLocalBaseUrl,
  clearStaleLocalPid,
  type LocalAgentPwConfig,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
  removeLocalPid,
  writeLocalPid,
} from './config'
import { serveLocalServer } from './serve'

export interface LocalServerStatus {
  configured: boolean
  running: boolean
  pid: number | null
  baseUrl: string | null
}

export function getLocalServerStatus(paths = localAgentPwPaths()): LocalServerStatus {
  const config = readLocalConfig(paths)
  clearStaleLocalPid(paths)
  const pid = readLocalPid(paths)

  return {
    configured: config !== null,
    running: pid !== null,
    pid,
    baseUrl: config ? buildLocalBaseUrl(config.port) : null,
  }
}

export async function probeLocalServer(baseUrl: string, timeoutMs = 1000) {
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

export async function waitForLocalServer(
  baseUrl: string,
  timeoutMs = 15_000,
  intervalMs = 250,
) {
  const startedAt = Date.now()

  while (Date.now() - startedAt < timeoutMs) {
    if (await probeLocalServer(baseUrl)) {
      return
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for agent.pw at ${baseUrl}`)
}

export function registerLocalServerProcess(paths = localAgentPwPaths()) {
  clearStaleLocalPid(paths)
  writeLocalPid(process.pid, paths)

  const cleanup = () => {
    removeLocalPid(paths)
  }

  const handleSignal = () => {
    cleanup()
    process.exit(0)
  }

  process.on('SIGINT', handleSignal)
  process.on('SIGTERM', handleSignal)
  process.on('exit', cleanup)
}

export async function serveLocalServerProcess(
  config: LocalAgentPwConfig,
  hostname = '0.0.0.0',
  paths = localAgentPwPaths(),
) {
  const server = await serveLocalServer(config, hostname)
  registerLocalServerProcess(paths)
  return server
}

export function stopLocalServer(paths = localAgentPwPaths()) {
  clearStaleLocalPid(paths)
  const pid = readLocalPid(paths)

  if (!pid) {
    return false
  }

  process.kill(pid, 'SIGTERM')
  removeLocalPid(paths)
  return true
}
