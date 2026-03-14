import { serve } from '@hono/node-server'
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

  return await new Promise((resolve, reject) => {
    let settled = false

    const server = serve({
      fetch: app.fetch,
      port: config.port,
      hostname,
    }, () => {
      if (settled) {
        return
      }

      settled = true
      server.off('error', onError)
      resolve(server)
    })

    const onError = (error: NodeJS.ErrnoException) => {
      if (settled) {
        return
      }

      settled = true

      if (error.code === 'EADDRINUSE') {
        reject(new Error(`Failed to start server. Is port ${config.port} in use?`))
        return
      }

      reject(error)
    }

    server.once('error', onError)
  })
}
