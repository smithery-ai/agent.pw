import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  localAgentPwPaths,
  readLocalConfig,
  type LocalAgentPwConfig,
} from '../../server/src/local/config'

export function readConfig(): LocalAgentPwConfig | null {
  return readLocalConfig()
}

const TOKEN_STACK_FILE = join(localAgentPwPaths().homeDir, 'token-stack.json')

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
  mkdirSync(localAgentPwPaths().homeDir, { recursive: true })
  if (stack.length === 0) {
    if (existsSync(TOKEN_STACK_FILE)) unlinkSync(TOKEN_STACK_FILE)
    return
  }
  writeFileSync(TOKEN_STACK_FILE, `${JSON.stringify(stack, null, 2)}\n`, { mode: 0o600 })
}
