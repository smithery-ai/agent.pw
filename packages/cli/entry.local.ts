import { createCoreApp } from '@agent.pw/server'
import { createLocalDb } from '@agent.pw/server/db'
import { migrateLocal } from '@agent.pw/server/db/migrate-local'
import { readConfig } from './src/config'

const config = readConfig()
if (!config) {
  console.error('Not set up. Run `agent.pw setup` first.')
  process.exit(1)
}

const db = await createLocalDb(config.dataDir)
await migrateLocal(db)

const app = createCoreApp({
  db,
  biscuitPrivateKey: config.biscuitPrivateKey,
  baseUrl: `http://local.agent.pw:${config.port}`,
})

Bun.serve({
  fetch: app.fetch,
  port: config.port,
  hostname: '0.0.0.0',
})

console.log(`agent.pw running at http://local.agent.pw:${config.port}`)
