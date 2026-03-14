const STUB_LOCAL_SERVER = `#!/usr/bin/env node
import { createServer } from 'node:http'
import { mkdirSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const homeDir = process.env.AGENTPW_HOME || join(homedir(), '.agent.pw')
const configFile = join(homeDir, 'config.json')
const pidFile = join(homeDir, 'agent.pw.pid')
const dataDir = join(homeDir, 'data')
const command = process.argv[2] || 'serve'

mkdirSync(homeDir, { recursive: true })
mkdirSync(dataDir, { recursive: true })

if (command === 'setup') {
  if (!existsSync(configFile)) {
    writeFileSync(configFile, JSON.stringify({
      biscuitPrivateKey: 'stub-private-key',
      masterToken: 'apw_stub_root',
      port: 9315,
      dataDir
    }, null, 2))
  }
  process.stdout.write(JSON.stringify({
    configDir: homeDir,
    configFile,
    dataDir,
    port: 9315
  }))
  process.exit(0)
}

if (command === 'bootstrap-token') {
  process.stdout.write('apw_stub_bootstrap')
  process.exit(0)
}

const config = JSON.parse(readFileSync(configFile, 'utf8'))

writeFileSync(pidFile, String(process.pid))

const cleanup = () => {
  try {
    unlinkSync(pidFile)
  } catch {}
}

process.on('SIGTERM', () => {
  cleanup()
  process.exit(0)
})
process.on('SIGINT', () => {
  cleanup()
  process.exit(0)
})
process.on('exit', cleanup)

const server = createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ ok: true, port: config.port }))
})

server.listen(config.port, '127.0.0.1')
`

import { readFileSync } from 'node:fs'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'

const packageDir = process.cwd()
const tempDir = await mkdtemp(join(tmpdir(), 'agentpw-cli-smoke-'))
let tarballPath

try {
  await run('npm', ['run', 'compile'], packageDir)
  const tarballName = (await run('npm', ['pack', '--silent'], packageDir)).stdout.trim().split('\n').at(-1)
  if (!tarballName) {
    throw new Error('npm pack did not produce a tarball name')
  }

  tarballPath = resolve(packageDir, tarballName)
  await writeFile(join(tempDir, 'package.json'), JSON.stringify({ name: 'agentpw-cli-smoke', private: true }, null, 2))

  await run('npm', ['install', tarballPath], tempDir)
  const cliEntrypoint = join(tempDir, 'node_modules', 'agent.pw', 'dist', 'index.js')

  const homeDir = join(tempDir, 'home')
  const preInit = await run('node', [cliEntrypoint, 'token'], tempDir, { HOME: homeDir })
  const preInitOutput = `${preInit.stdout}${preInit.stderr}`

  if (preInit.exitCode === 0) {
    throw new Error('Expected agent.pw token to exit non-zero without configuration')
  }

  if (!preInitOutput.includes('Run `npx agent.pw init`')) {
    throw new Error(`Unexpected packaged CLI pre-init output:\n${preInitOutput}`)
  }

  const stubServerPath = join(tempDir, 'stub-local-server.mjs')
  await writeFile(stubServerPath, STUB_LOCAL_SERVER)
  await chmod(stubServerPath, 0o755)

  const init = await run(
    'node',
    [cliEntrypoint, 'init', '--no-browser'],
    tempDir,
    {
      HOME: homeDir,
      AGENTPW_SKIP_SKILL_INSTALL: '1',
      AGENTPW_SERVER_BINARY_PATH: stubServerPath,
      AGENTPW_VAULT_URL: 'https://agent.pw/vault',
    },
  )

  const initOutput = `${init.stdout}${init.stderr}`
  if (init.exitCode !== 0) {
    throw new Error(`agent.pw init failed:\n${initOutput}`)
  }

  if (!initOutput.includes('https://agent.pw/vault?url=')) {
    throw new Error(`Expected init output to include vault URL:\n${initOutput}`)
  }

  const configPath = join(homeDir, '.agent.pw', 'config.json')
  const configText = readFileSync(configPath, 'utf8')
  if (!configText.includes('"port": 9315')) {
    throw new Error(`Expected init to write local config:\n${configText}`)
  }
} finally {
  if (tarballPath) {
    await rm(tarballPath, { force: true })
  }
  await rm(tempDir, { recursive: true, force: true })
}

function run(command, args, cwd, env = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', chunk => {
      stdout += chunk
    })
    child.stderr.on('data', chunk => {
      stderr += chunk
    })

    child.on('exit', exitCode => {
      resolvePromise({ exitCode: exitCode ?? 1, stdout, stderr })
    })
    child.on('error', reject)
  })
}
