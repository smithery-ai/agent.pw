import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

export interface AgentPwConfig {
  biscuitPrivateKey: string
  masterToken: string
  port: number
  dataDir: string
}

const CONFIG_DIR = join(homedir(), '.agent.pw')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')
const PID_FILE = join(CONFIG_DIR, 'agent.pw.pid')

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

export function readConfig(): AgentPwConfig | null {
  if (!existsSync(CONFIG_FILE)) return null
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'))
  } catch {
    return null
  }
}

export function writeConfig(config: AgentPwConfig) {
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

// ─── Token Stack ─────────────────────────────────────────────────────────

const TOKEN_STACK_FILE = join(CONFIG_DIR, 'token-stack.json')

export function readTokenStack(): string[] {
  if (!existsSync(TOKEN_STACK_FILE)) return []
  try {
    const data = JSON.parse(readFileSync(TOKEN_STACK_FILE, 'utf-8'))
    return Array.isArray(data) ? data : []
  } catch {
    return []
  }
}

export function writeTokenStack(stack: string[]) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  if (stack.length === 0) {
    if (existsSync(TOKEN_STACK_FILE)) unlinkSync(TOKEN_STACK_FILE)
    return
  }
  writeFileSync(TOKEN_STACK_FILE, `${JSON.stringify(stack, null, 2)}\n`, { mode: 0o600 })
}
