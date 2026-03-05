import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

export interface WardenConfig {
  biscuitPrivateKey: string
  masterToken: string
  port: number
  dataDir: string
}

const CONFIG_DIR = join(homedir(), '.agent.pw')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')
const PID_FILE = join(CONFIG_DIR, 'warden.pid')

export function getConfigDir() {
  return CONFIG_DIR
}

export function getDataDir() {
  return join(CONFIG_DIR, 'data')
}

export function getPidFile() {
  return PID_FILE
}

export function configExists() {
  return existsSync(CONFIG_FILE)
}

export function readConfig(): WardenConfig | null {
  if (!existsSync(CONFIG_FILE)) return null
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'))
  } catch {
    return null
  }
}

export function writeConfig(config: WardenConfig) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 })
}

// ─── Managed Session ──────────────────────────────────────────────────────

export interface ManagedSession {
  host: string
  token: string
}

const SESSION_FILE = join(CONFIG_DIR, 'session.json')

export function readManagedSession(): ManagedSession | null {
  if (!existsSync(SESSION_FILE)) return null
  try {
    return JSON.parse(readFileSync(SESSION_FILE, 'utf-8'))
  } catch {
    return null
  }
}

export function writeManagedSession(session: ManagedSession) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(SESSION_FILE, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 })
}

export function clearManagedSession() {
  if (existsSync(SESSION_FILE)) {
    unlinkSync(SESSION_FILE)
  }
}
