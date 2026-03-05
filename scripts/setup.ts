/**
 * Bootstrap script: generates a root management token from BISCUIT_PRIVATE_KEY.
 *
 * Usage: BISCUIT_PRIVATE_KEY=... npx tsx scripts/setup.ts
 *   or:  pnpm run setup  (with .env configured)
 */

import { generateKeyPairHex, mintManagementToken } from '../src/biscuit'

const privateKey = process.env.BISCUIT_PRIVATE_KEY

if (!privateKey) {
  console.log('No BISCUIT_PRIVATE_KEY found. Generating a new keypair:\n')
  const kp = generateKeyPairHex()
  console.log(`BISCUIT_PRIVATE_KEY=${kp.privateKey}`)
  console.log(`BISCUIT_PUBLIC_KEY=${kp.publicKey}`)
  console.log('\nAdd BISCUIT_PRIVATE_KEY to your .env, then re-run this script.')
  process.exit(0)
}

const rootToken = mintManagementToken(
  privateKey,
  ['manage_services', 'manage_vaults'],
  ['*'],
)

console.log('Root management token (store securely):\n')
console.log(rootToken)
console.log('\nThis token can manage all services and vaults.')
