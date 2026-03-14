import { execSync } from 'node:child_process'

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
  if (process.env.AGENTPW_SKIP_SKILL_INSTALL === '1') {
    return
  }

  execSync('npx -y @smithery/cli@latest skill add smithery-ai/agentpw', {
    stdio: 'inherit',
  })
}

export function printOnboardingHeader() {
  console.log('Preparing your local agent.pw instance...')
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
