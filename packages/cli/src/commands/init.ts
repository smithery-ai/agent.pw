import { execSync } from 'node:child_process'
import { resolveOptional } from '../resolve'

export async function init() {
  // Step 1: Ensure logged in
  const endpoint = await resolveOptional()
  if (!endpoint) {
    console.log('Not logged in. Starting login...')
    console.log('')
    const { login } = await import('./login')
    await login(undefined, undefined, { skipNextSteps: true })
    console.log('')
  }

  // Step 2: Install the skill from the Smithery registry
  console.log('Installing agent.pw skill...')
  try {
    execSync('npx @smithery/cli@latest skill add smithery-ai/agentpw', {
      stdio: 'inherit',
    })
  } catch {
    console.error('Failed to install skill. You can install it manually:')
    console.error('  npx @smithery/cli@latest skill add smithery-ai/agentpw')
    process.exit(1)
  }
}
