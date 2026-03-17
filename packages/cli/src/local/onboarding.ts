import { execSync } from 'node:child_process'
import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'

const AGENTPW_SKILL_INSTALL_COMMAND = 'npx -y @smithery/cli@latest skill add smithery-ai/agentpw'

export function buildCliHelpFooter() {
  return [
    '',
    'New here?',
    '  npx agent.pw start',
    '  Open setup in your browser and connect your first API.',
    '  If you use Smithery, you can also install the agentpw skill now:',
    `  ${AGENTPW_SKILL_INSTALL_COMMAND}`,
  ].join('\n')
}

export function buildCliWelcomeMessage() {
  return [
    'Welcome to agent.pw.',
    '',
    'agent.pw lets your AI agent use APIs without seeing your raw API keys.',
    '',
    'To get started:',
    '  npx agent.pw start',
    '',
    'This opens setup in your browser so you can connect your first API and get a token for your agent.',
    '',
    'If you use Smithery, you can also install the agentpw skill now:',
    `  ${AGENTPW_SKILL_INSTALL_COMMAND}`,
    '',
    'Need the full command list?',
    '  npx agent.pw --help',
  ].join('\n')
}

export function printCliWelcome() {
  console.log(buildCliWelcomeMessage())
}

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

async function promptYesNo(question: string) {
  if (!(process.stdin.isTTY && process.stdout.isTTY)) {
    return false
  }

  const readline = createInterface({ input, output })

  try {
    const answer = await readline.question(question)
    const normalized = answer.trim().toLowerCase()
    return normalized === 'y' || normalized === 'yes'
  } finally {
    readline.close()
  }
}

export async function confirmTakeoverRunningProcess(baseUrl: string) {
  return promptYesNo(
    `A process is already responding at ${baseUrl}, but agent.pw is not managing it. Kill it and continue with managed setup? [y/N] `,
  )
}

export function printAgentPwSkillInstallHint() {
  console.log('Optional: install the Smithery skill later with:')
  console.log(`  ${AGENTPW_SKILL_INSTALL_COMMAND}`)
}

export function printOnboardingHeader() {
  console.log('Setting up agent.pw...')
  console.log('This can take a minute the first time.')
  console.log('This window will say "agent.pw is ready." when setup is complete.')
  console.log('')
}

export function printOnboardingStep(message: string) {
  console.log(message)
}

export function printOnboardingSuccess(url: string, browserOpened: boolean) {
  console.log('')
  console.log('agent.pw is ready.')
  console.log(`Vault: ${url}`)
  console.log(browserOpened ? 'Opened the vault in your browser.' : 'Open the vault URL above to continue.')
}

export function printBinarySource(
  source: 'bundle' | 'source',
  _displayPath: string,
) {
  const label = source === 'bundle'
    ? '[1/3] Loading setup tools...'
    : '[1/3] Loading setup tools from this checkout...'

  console.log(label)
}
