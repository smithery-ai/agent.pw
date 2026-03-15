import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export interface LocalAgentPwConfig {
  biscuitPrivateKey: string
  port: number
  dataDir: string
}

export interface LegacyLocalAgentPwConfig extends LocalAgentPwConfig {
  masterToken?: string
}

export interface LocalAgentPwPaths {
  homeDir: string
  serverConfigFile: string
  cliConfigFile: string
  legacyConfigFile: string
  configFile: string
  pidFile: string
  dataDir: string
  logsDir: string
  logFile: string
  runtimeDir: string
  serverRuntimeDir: string
}

export const DEFAULT_LOCAL_PORT = 9315

export function resolveAgentPwHome() {
  const configured = process.env.AGENTPW_HOME?.trim()
  return configured || join(homedir(), '.agent.pw')
}

export function resolveLocalPort(defaultPort = DEFAULT_LOCAL_PORT) {
  const configured = process.env.AGENTPW_LOCAL_PORT?.trim()
  if (!configured) {
    return defaultPort
  }

  const parsed = Number.parseInt(configured, 10)
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new Error(`Invalid AGENTPW_LOCAL_PORT: ${configured}`)
  }

  return parsed
}

export function localAgentPwPaths(homeDir = resolveAgentPwHome()): LocalAgentPwPaths {
  const serverConfigFile = join(homeDir, 'server.json')

  return {
    homeDir,
    serverConfigFile,
    cliConfigFile: join(homeDir, 'cli.json'),
    legacyConfigFile: join(homeDir, 'config.json'),
    configFile: serverConfigFile,
    pidFile: join(homeDir, 'agent.pw.pid'),
    dataDir: join(homeDir, 'data'),
    logsDir: join(homeDir, 'logs'),
    logFile: join(homeDir, 'logs', 'server.log'),
    runtimeDir: join(homeDir, 'runtime'),
    serverRuntimeDir: join(homeDir, 'runtime', 'server'),
  }
}

export function ensureLocalAgentPwDirs(paths = localAgentPwPaths()) {
  mkdirSync(paths.homeDir, { recursive: true })
  mkdirSync(paths.dataDir, { recursive: true })
  mkdirSync(paths.logsDir, { recursive: true })
  mkdirSync(paths.runtimeDir, { recursive: true })
  mkdirSync(paths.serverRuntimeDir, { recursive: true })
}

function readJsonFile<T>(filePath: string) {
  if (!existsSync(filePath)) return null

  try {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T
  } catch {
    return null
  }
}

export function readLegacyLocalConfig(paths = localAgentPwPaths()) {
  return readJsonFile<LegacyLocalAgentPwConfig>(paths.legacyConfigFile)
}

export function migrateLegacyLocalServerConfig(paths = localAgentPwPaths()) {
  const legacyConfig = readLegacyLocalConfig(paths)
  if (!legacyConfig) {
    return null
  }

  const config: LocalAgentPwConfig = {
    biscuitPrivateKey: legacyConfig.biscuitPrivateKey,
    port: legacyConfig.port,
    dataDir: legacyConfig.dataDir,
  }

  writeLocalConfig(config, paths)
  return config
}

export function readLocalConfig(paths = localAgentPwPaths()) {
  return readJsonFile<LocalAgentPwConfig>(paths.serverConfigFile)
    ?? migrateLegacyLocalServerConfig(paths)
}

export function writeLocalConfig(
  config: LocalAgentPwConfig,
  paths = localAgentPwPaths(),
) {
  ensureLocalAgentPwDirs(paths)
  writeFileSync(
    paths.serverConfigFile,
    `${JSON.stringify(config, null, 2)}\n`,
    { mode: 0o600 },
  )
}

export function removeLegacyLocalConfig(paths = localAgentPwPaths()) {
  if (!existsSync(paths.legacyConfigFile)) return
  unlinkSync(paths.legacyConfigFile)
}

export function readLocalPid(paths = localAgentPwPaths()) {
  if (!existsSync(paths.pidFile)) return null

  try {
    const raw = readFileSync(paths.pidFile, 'utf8').trim()
    const pid = Number.parseInt(raw, 10)
    return Number.isInteger(pid) && pid > 0 ? pid : null
  } catch {
    return null
  }
}

export function writeLocalPid(pid: number, paths = localAgentPwPaths()) {
  ensureLocalAgentPwDirs(paths)
  writeFileSync(paths.pidFile, `${pid}\n`)
}

export function removeLocalPid(paths = localAgentPwPaths()) {
  if (!existsSync(paths.pidFile)) return
  unlinkSync(paths.pidFile)
}

export function isProcessAlive(pid: number) {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

export function clearStaleLocalPid(paths = localAgentPwPaths()) {
  const pid = readLocalPid(paths)
  if (!pid) return false
  if (isProcessAlive(pid)) return false

  removeLocalPid(paths)
  return true
}

export function buildLocalBaseUrl(port: number) {
  return `http://127.0.0.1:${port}`
}

export function writeExecutableFile(
  filePath: string,
  contents: string | Uint8Array,
) {
  mkdirSync(dirname(filePath), { recursive: true })
  writeFileSync(filePath, contents, { mode: 0o755 })
}
