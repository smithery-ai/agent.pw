import { chmod, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { spawn } from 'node:child_process'

const outfileFlagIndex = process.argv.indexOf('--outfile')
if (outfileFlagIndex === -1 || !process.argv[outfileFlagIndex + 1]) {
  throw new Error('Usage: node scripts/build-local-server-binary.mjs --outfile <path>')
}

const outputPath = resolve(process.argv[outfileFlagIndex + 1])

await mkdir(dirname(outputPath), { recursive: true })
await run('bun', [
  'build',
  '--compile',
  'packages/server/entry.local.ts',
  '--outfile',
  outputPath,
])

if (process.platform !== 'win32') {
  await chmod(outputPath, 0o755)
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      stdio: 'inherit',
      env: process.env,
    })

    child.on('error', reject)
    child.on('exit', code => {
      if (code === 0) {
        resolvePromise()
        return
      }

      reject(new Error(`${command} ${args.join(' ')} exited with code ${code ?? 'null'}`))
    })
  })
}
