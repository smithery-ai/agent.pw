import { execSync } from 'node:child_process'
import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'

export function canOpenBrowser() {
  return Boolean(
    process.stdout.isTTY
    && !process.env.SSH_CLIENT
    && !process.env.SSH_TTY
    && !process.env.CODESPACES
    && !process.env.REMOTE_CONTAINERS,
  )
}

export function openBrowser(url: string) {
  if (!canOpenBrowser()) {
    return false
  }

  const quotedUrl = JSON.stringify(url)
  const command = process.platform === 'darwin'
    ? `open ${quotedUrl}`
    : process.platform === 'win32'
      ? `start "" ${quotedUrl}`
      : `xdg-open ${quotedUrl}`

  try {
    execSync(command, {
      stdio: 'ignore',
      timeout: 5_000,
    })
    return true
  } catch {
    return false
  }
}

export function installAgentPwSkill() {
  execSync('npx -y @smithery/cli@latest skill add smithery-ai/agentpw', {
    stdio: 'inherit',
  })
}

export async function confirmAgentPwSkillInstall() {
  if (process.env.AGENTPW_SKIP_SKILL_INSTALL === '1') {
    return false
  }

  if (!(process.stdin.isTTY && process.stdout.isTTY)) {
    return false
  }

  const readline = createInterface({ input, output })

  try {
    const answer = await readline.question('Install the optional Smithery skill now? [y/N] ')
    const normalized = answer.trim().toLowerCase()
    return normalized === 'y' || normalized === 'yes'
  } finally {
    readline.close()
  }
}

export function printAgentPwSkillInstallHint() {
  console.log('Optional: install the Smithery skill later with:')
  console.log('  npx -y @smithery/cli@latest skill add smithery-ai/agentpw')
}

export function printOnboardingHeader() {
  console.log('Installing or repairing your local agent.pw service...')
  console.log('')
}

export function printOnboardingSuccess(url: string, browserOpened: boolean) {
  console.log('')
  console.log('agent.pw is ready.')
  console.log(`Vault: ${url}`)
  console.log(browserOpened ? 'Opened the vault in your browser.' : 'Open the vault URL above to continue.')
}

export function printBinarySource(
  source: 'bundle' | 'source',
  displayPath: string,
) {
  const label = source === 'bundle'
    ? 'Using bundled local daemon'
    : 'Using source-checkout local daemon'

  console.log(`${label}: ${displayPath}`)
}
