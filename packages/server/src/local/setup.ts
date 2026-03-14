import { generateKeyPairHex, getPublicKeyHex, mintToken, restrictToken } from '../biscuit'
import { createLocalDb } from '../db/index'
import { migrateLocal } from '../db/migrate-local'
import type { TokenRight } from '../core/types'
import {
  DEFAULT_LOCAL_PORT,
  type LocalAgentPwConfig,
  type LocalAgentPwPaths,
  ensureLocalAgentPwDirs,
  localAgentPwPaths,
  readLocalConfig,
  resolveLocalPort,
  writeLocalConfig,
} from './config'

const ROOT_RIGHTS: TokenRight[] = [
  { action: 'credential.use', root: '/' },
  { action: 'credential.bootstrap', root: '/' },
  { action: 'credential.manage', root: '/' },
  { action: 'profile.manage', root: '/' },
  { action: 'token.mint', root: '/' },
]

const ROOT_FACTS = ['home_path("/")']

export async function initializeLocalConfig(
  paths = localAgentPwPaths(),
  port = resolveLocalPort(DEFAULT_LOCAL_PORT),
) {
  const existing = readLocalConfig(paths)
  if (existing) return existing

  ensureLocalAgentPwDirs(paths)

  const keypair = generateKeyPairHex()
  const db = await createLocalDb(paths.dataDir)
  await migrateLocal(db)

  const config: LocalAgentPwConfig = {
    biscuitPrivateKey: keypair.privateKey,
    masterToken: mintToken(keypair.privateKey, 'local', ROOT_RIGHTS, ROOT_FACTS),
    port,
    dataDir: paths.dataDir,
  }

  writeLocalConfig(config, paths)
  return config
}

export async function ensureLocalConfig(paths = localAgentPwPaths()) {
  return initializeLocalConfig(paths)
}

export function mintBootstrapToken(
  config: LocalAgentPwConfig,
  ttl = '10m',
) {
  const publicKeyHex = getPublicKeyHex(config.biscuitPrivateKey)
  return restrictToken(config.masterToken, publicKeyHex, [{
    actions: '_management',
    services: '_management',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    paths: [
      '/credentials',
      '/cred_profiles',
      '/tokens/inspect',
      '/tokens/restrict',
      '/tokens/revoke',
    ],
    ttl,
  }])
}

export function localConfigSummary(
  config: LocalAgentPwConfig,
  paths: LocalAgentPwPaths = localAgentPwPaths(),
) {
  return {
    configDir: paths.homeDir,
    configFile: paths.configFile,
    dataDir: config.dataDir,
    port: config.port,
  }
}
