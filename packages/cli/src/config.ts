import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildLocalBaseUrl,
  localAgentPwPaths,
  readLegacyLocalConfig,
  readLocalConfig,
  removeLegacyLocalConfig,
  type LocalAgentPwConfig,
  type LocalAgentPwPaths,
} from '../../server/src/local/config'
import { mintLocalRootToken } from '../../server/src/local/setup'

export interface AgentPwCliConfig {
  url: string
  token: string
}

function tokenStackFile(paths = localAgentPwPaths()) {
  return join(paths.homeDir, 'token-stack.json')
}

export function readCliConfig(paths = localAgentPwPaths()): AgentPwCliConfig | null {
  if (existsSync(paths.cliConfigFile)) {
    try {
      return JSON.parse(readFileSync(paths.cliConfigFile, 'utf-8')) as AgentPwCliConfig
    } catch {
      return null
    }
  }

  const legacyConfig = readLegacyLocalConfig(paths)
  if (!legacyConfig?.masterToken) {
    return null
  }

  readLocalConfig(paths)
  const cliConfig = {
    url: buildLocalBaseUrl(legacyConfig.port),
    token: legacyConfig.masterToken,
  }
  writeCliConfig(cliConfig, paths)
  if (existsSync(paths.serverConfigFile)) {
    removeLegacyLocalConfig(paths)
  }
  return cliConfig
}

export function writeCliConfig(
  config: AgentPwCliConfig,
  paths = localAgentPwPaths(),
) {
  mkdirSync(paths.homeDir, { recursive: true })
  writeFileSync(paths.cliConfigFile, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 })
}

export function ensureLocalCliConfig(
  config: LocalAgentPwConfig,
  paths: LocalAgentPwPaths = localAgentPwPaths(),
) {
  const cliConfig = {
    url: buildLocalBaseUrl(config.port),
    token: mintLocalRootToken(config),
  }

  writeCliConfig(cliConfig, paths)
  if (existsSync(paths.serverConfigFile)) {
    removeLegacyLocalConfig(paths)
  }

  return cliConfig
}

export function readConfig() {
  return readCliConfig()
}

export function readTokenStack(): string[] {
  const file = tokenStackFile()
  if (!existsSync(file)) return []
  try {
    const data = JSON.parse(readFileSync(file, 'utf-8'))
    return Array.isArray(data) ? data : []
  } catch {
    return []
  }
}

export function writeTokenStack(stack: string[]) {
  const paths = localAgentPwPaths()
  const file = tokenStackFile(paths)
  mkdirSync(paths.homeDir, { recursive: true })
  if (stack.length === 0) {
    if (existsSync(file)) unlinkSync(file)
    return
  }
  writeFileSync(file, `${JSON.stringify(stack, null, 2)}\n`, { mode: 0o600 })
}
