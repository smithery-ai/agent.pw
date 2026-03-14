import { createCoreApp } from '../core/app'
import { createLocalDb } from '../db/index'
import { migrateLocal } from '../db/migrate-local'
import { buildLocalBaseUrl, type LocalAgentPwConfig } from './config'

export async function createLocalServerApp(config: LocalAgentPwConfig) {
  const db = await createLocalDb(config.dataDir)
  await migrateLocal(db)

  return createCoreApp({
    db,
    biscuitPrivateKey: config.biscuitPrivateKey,
    baseUrl: buildLocalBaseUrl(config.port),
  })
}

export async function serveLocalServer(
  config: LocalAgentPwConfig,
  hostname = '0.0.0.0',
) {
  const app = await createLocalServerApp(config)

  return Bun.serve({
    fetch: app.fetch,
    port: config.port,
    hostname,
  })
}
