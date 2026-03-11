#!/usr/bin/env bun

import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { Command } from 'commander'

// ─── Config ──────────────────────────────────────────────────────────────────

interface AgentPwConfig {
  biscuitPrivateKey: string
  masterToken: string
  port: number
  dataDir: string
}

const CONFIG_DIR = join(homedir(), '.agent.pw')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')
const PID_FILE = join(CONFIG_DIR, 'agent.pw.pid')
const DATA_DIR = join(CONFIG_DIR, 'data')

function readConfig(): AgentPwConfig | null {
  if (!existsSync(CONFIG_FILE)) return null
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'))
  } catch {
    return null
  }
}

function writeConfig(config: AgentPwConfig) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 })
}

// ─── Program ─────────────────────────────────────────────────────────────────

const program = new Command()
  .name('agent.pw-server')
  .description('Self-hosted agent.pw server')
  .version('0.1.0')

program
  .command('setup')
  .description('Set up a local instance (keys, database)')
  .action(async () => {
    if (existsSync(CONFIG_FILE)) {
      console.log('agent.pw is already set up. Config at:', CONFIG_DIR)
      console.log('Run `agent.pw-server start` to start the local server.')
      return
    }

    console.log('Setting up agent.pw...\n')

    const { generateKeyPairHex, mintToken } = await import('./src/biscuit')
    const { createLocalDb } = await import('./src/db/index')
    const { migrateLocal } = await import('./src/db/migrate-local')

    const keypair = generateKeyPairHex()

    mkdirSync(DATA_DIR, { recursive: true })
    console.log('Initializing database at', DATA_DIR)
    const db = await createLocalDb(DATA_DIR)
    await migrateLocal(db)

    const masterToken = mintToken(keypair.privateKey, 'local', ['manage_services'])
    const port = 9315

    writeConfig({
      biscuitPrivateKey: keypair.privateKey,
      masterToken,
      port,
      dataDir: DATA_DIR,
    })

    console.log('\nagent.pw is set up!\n')
    console.log('Config saved to:', CONFIG_DIR)
    console.log('Master token:', masterToken)
    console.log('\nNext steps:')
    console.log('  agent.pw-server start   Start the local proxy server')
    console.log('  agent.pw cred add       Add API credentials')
    console.log('  agent.pw curl <url>     Make authenticated API calls')
  })

program
  .command('start')
  .description('Start the local proxy server')
  .action(async () => {
    const config = readConfig()
    if (!config) {
      console.error('Not set up. Run `agent.pw-server setup` first.')
      process.exit(1)
    }

    if (existsSync(PID_FILE)) {
      const pid = parseInt(readFileSync(PID_FILE, 'utf-8').trim(), 10)
      try {
        process.kill(pid, 0)
        console.error(`agent.pw is already running (PID ${pid}). Stop it with \`agent.pw-server stop\`.`)
        process.exit(1)
      } catch {
        unlinkSync(PID_FILE)
      }
    }

    const { createCoreApp } = await import('./src/core/app')
    const { createLocalDb } = await import('./src/db/index')
    const { migrateLocal } = await import('./src/db/migrate-local')

    const db = await createLocalDb(config.dataDir)
    await migrateLocal(db)

    const app = createCoreApp({
      db,
      biscuitPrivateKey: config.biscuitPrivateKey,
      baseUrl: `http://local.agent.pw:${config.port}`,
    })

    writeFileSync(PID_FILE, process.pid.toString())

    const cleanup = () => {
      try { unlinkSync(PID_FILE) } catch { /* already removed */ }
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
  })

program
  .command('stop')
  .description('Stop the local proxy server')
  .action(async () => {
    if (!existsSync(PID_FILE)) {
      console.log('agent.pw is not running.')
      return
    }

    const pid = parseInt(readFileSync(PID_FILE, 'utf-8').trim(), 10)
    try {
      process.kill(pid, 'SIGTERM')
      console.log(`Stopped agent.pw (PID ${pid}).`)
    } catch {
      console.log('agent.pw process not found. Cleaning up PID file.')
    }
    try { unlinkSync(PID_FILE) } catch { /* ignore */ }
  })

program.parseAsync().catch(err => {
  console.error(err.message ?? err)
  process.exit(1)
})
