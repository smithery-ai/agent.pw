import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'

const packageDir = process.cwd()
const tempDir = await mkdtemp(join(tmpdir(), 'agentpw-cli-smoke-'))
let tarballPath

try {
  const tarballName = (await run('npm', ['pack', '--silent'], packageDir)).stdout.trim().split('\n').at(-1)
  if (!tarballName) {
    throw new Error('npm pack did not produce a tarball name')
  }

  tarballPath = resolve(packageDir, tarballName)
  await writeFile(join(tempDir, 'package.json'), JSON.stringify({ name: 'agentpw-cli-smoke', private: true }, null, 2))

  await run('npm', ['install', tarballPath], tempDir)

  const homeDir = join(tempDir, 'home')
  const result = await run('npx', ['agent.pw', 'token'], tempDir, { HOME: homeDir })
  const combinedOutput = `${result.stdout}${result.stderr}`

  if (result.exitCode === 0) {
    throw new Error('Expected agent.pw token to exit non-zero without configuration')
  }

  if (!combinedOutput.includes('No agent.pw instance available.')) {
    throw new Error(`Unexpected packaged CLI output:\n${combinedOutput}`)
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
