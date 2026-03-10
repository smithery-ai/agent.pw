import { spawn } from 'node:child_process'
import { createCoreApp } from '../packages/server/src/core/app'
import { BISCUIT_PRIVATE_KEY, ORG_TOKEN, createTestDb } from '../test/setup'

const PORT = 9315
const HOST = `http://127.0.0.1:${PORT}`

async function main() {
  const db = await createTestDb()
  const app = createCoreApp({
    db,
    biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    baseUrl: HOST,
  })

  const server = Bun.serve({
    fetch: app.fetch,
    port: PORT,
    hostname: '127.0.0.1',
  })

  console.log(`Local smoke server running at ${HOST}`)
  console.log('Inspecting a freshly minted org-scoped token via CLI source:')
  console.log()

  const child = spawn('bun', ['packages/cli/src/index.ts', 'token'], {
    cwd: import.meta.dirname + '/..',
    stdio: 'inherit',
    env: {
      ...process.env,
      AGENT_PW_HOST: HOST,
      AGENT_PW_TOKEN: ORG_TOKEN,
    },
  })

  const exitCode = await new Promise<number>((resolve, reject) => {
    child.on('error', reject)
    child.on('exit', code => resolve(code ?? 1))
  })

  await server.stop(true)
  process.exit(exitCode)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
