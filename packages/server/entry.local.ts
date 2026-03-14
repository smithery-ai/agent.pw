import { localConfigSummary, ensureLocalConfig, mintBootstrapToken } from './src/local/setup'
import { readLocalConfig } from './src/local/config'
import { serveLocalServerProcess } from './src/local/runtime'

const [command = 'serve', ...args] = process.argv.slice(2)

switch (command) {
  case 'setup':
    await setup()
    break
  case 'bootstrap-token':
    await bootstrapToken(args)
    break
  case 'serve':
    await serve()
    break
  default:
    console.error(`Unknown command: ${command}`)
    process.exit(1)
}

async function setup() {
  const config = await ensureLocalConfig()
  const summary = localConfigSummary(config)
  console.log(JSON.stringify(summary))
}

async function bootstrapToken(argv: string[]) {
  const config = readLocalConfig()
  if (!config) {
    console.error('agent.pw is not initialized. Run `npx agent.pw init` first.')
    process.exit(1)
  }

  const ttl = readFlag(argv, '--ttl') ?? '10m'
  console.log(mintBootstrapToken(config, ttl))
}

async function serve() {
  const config = readLocalConfig()
  if (!config) {
    console.error('agent.pw is not initialized. Run `npx agent.pw init` first.')
    process.exit(1)
  }

  await serveLocalServerProcess(config)
  console.log(`agent.pw local server running on http://127.0.0.1:${config.port}`)
}

function readFlag(argv: string[], flag: string) {
  const index = argv.indexOf(flag)
  if (index === -1) {
    return null
  }

  return argv[index + 1] ?? null
}
