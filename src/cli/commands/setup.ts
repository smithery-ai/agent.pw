import { mkdirSync } from 'node:fs'
import { generateKeyPairHex, mintManagementToken } from '../../biscuit'
import { createLocalDb } from '../../db/index'
import { migrateLocal } from '../../db/migrate-local'
import { configExists, writeConfig, getConfigDir, getDataDir } from '../config'

export async function setup() {
  if (configExists()) {
    console.log('agent.pw is already set up. Config at:', getConfigDir())
    console.log('Run `agent.pw start` to start the local server.')
    return
  }

  console.log('Setting up agent.pw...\n')

  // Generate cryptographic keys
  const keypair = generateKeyPairHex()

  // Initialize local database
  const dataDir = getDataDir()
  mkdirSync(dataDir, { recursive: true })
  console.log('Initializing database at', dataDir)
  const db = await createLocalDb(dataDir)
  await migrateLocal(db)

  // Mint root token: management rights + wildcard proxy grant
  const masterToken = mintManagementToken(
    keypair.privateKey,
    ['manage_services', 'manage_vaults'],
    ['*'],
    [{ vault: 'local' }],
  )

  const port = 9315

  writeConfig({
    biscuitPrivateKey: keypair.privateKey,
    masterToken,
    port,
    dataDir,
  })

  console.log('\nagent.pw is set up!\n')
  console.log('Config saved to:', getConfigDir())
  console.log('Master token:', masterToken)
  console.log('\nNext steps:')
  console.log('  agent.pw start        Start the local proxy server')
  console.log('  agent.pw creds add    Add API credentials')
  console.log('  agent.pw curl <url>   Make authenticated API calls')
}
