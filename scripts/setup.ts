/**
 * Bootstrap script: generates a root token from BISCUIT_PRIVATE_KEY.
 *
 * Usage: BISCUIT_PRIVATE_KEY=... npx tsx scripts/setup.ts
 *   or:  pnpm run setup  (with .env configured)
 */

import { generateKeyPairHex, mintToken } from '../packages/server/src/biscuit'

const privateKey = process.env.BISCUIT_PRIVATE_KEY

if (!privateKey) {
  console.log('No BISCUIT_PRIVATE_KEY found. Generating a new keypair:\n')
  const kp = generateKeyPairHex()
  console.log(`BISCUIT_PRIVATE_KEY=${kp.privateKey}`)
  console.log(`BISCUIT_PUBLIC_KEY=${kp.publicKey}`)
  console.log('\nAdd BISCUIT_PRIVATE_KEY to your .env, then re-run this script.')
  process.exit(0)
}

const rootToken = mintToken(
  privateKey,
  'local',
  [
    { action: 'credential.use', root: '/' },
    { action: 'credential.bootstrap', root: '/' },
    { action: 'credential.manage', root: '/' },
    { action: 'profile.manage', root: '/' },
    { action: 'token.mint', root: '/' },
  ],
)

console.log('Root token (store securely):\n')
console.log(rootToken)
console.log('\nThis token has root rights for credentials, profiles, and token minting.')
