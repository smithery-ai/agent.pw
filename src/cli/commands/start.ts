import { writeFileSync, existsSync, readFileSync, unlinkSync } from 'node:fs'
import { createApp } from '../../managed/app'
import { createLocalDb } from '../../db/index'
import { migrateLocal } from '../../db/migrate-local'
import { readConfig, getPidFile } from '../config'

export async function start() {
  const config = readConfig()
  if (!config) {
    console.error('Not set up. Run `agent.pw setup` first.')
    process.exit(1)
  }

  // Check if already running
  const pidFile = getPidFile()
  if (existsSync(pidFile)) {
    const pid = parseInt(readFileSync(pidFile, 'utf-8').trim(), 10)
    try {
      process.kill(pid, 0) // Check if process exists
      console.error(`agent.pw is already running (PID ${pid}). Stop it with \`agent.pw stop\`.`)
      process.exit(1)
    } catch {
      // Process doesn't exist, clean up stale PID file
      unlinkSync(pidFile)
    }
  }

  const db = await createLocalDb(config.dataDir)
  await migrateLocal(db)

  const app = createApp({
    db,
    biscuitPrivateKey: config.biscuitPrivateKey,
    baseUrl: `http://local.agent.pw:${config.port}`,
  })

  // Write PID file
  writeFileSync(pidFile, process.pid.toString())

  // Clean up on exit
  const cleanup = () => {
    try { unlinkSync(pidFile) } catch { /* already removed */ }
  }
  process.on('SIGINT', () => { cleanup(); process.exit(0) })
  process.on('SIGTERM', () => { cleanup(); process.exit(0) })

  Bun.serve({
    fetch: app.fetch,
    port: config.port,
    hostname: '0.0.0.0',
  })

  console.log(`agent.pw running at http://local.agent.pw:${config.port}`)
  console.log('Press Ctrl+C to stop.')
}
