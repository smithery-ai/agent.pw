import { cp, mkdir, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const packageDir = dirname(__dirname)
const distDir = join(packageDir, 'dist')
const vendorDir = join(distDir, 'vendor', 'biscuit-wasm')

const require = createRequire(import.meta.url)
const smitheryShim = require.resolve('@smithery/biscuit/shim')
const smitheryRequire = createRequire(smitheryShim)
const biscuitJs = smitheryRequire.resolve('@biscuit-auth/biscuit-wasm/module/biscuit_bg.js')
const biscuitWasm = smitheryRequire.resolve('@biscuit-auth/biscuit-wasm/module/biscuit_bg.wasm')

const bunArgs = process.argv.includes('--binary')
  ? ['build', '--compile', 'src/index.ts', '--outfile', 'dist/agent.pw']
  : ['build', 'src/index.ts', '--outdir', 'dist', '--target', 'node', '--format', 'esm', '--banner', '#!/usr/bin/env node']

await rm(vendorDir, { recursive: true, force: true })
await run('bun', bunArgs, packageDir)
await mkdir(vendorDir, { recursive: true })
await Promise.all([
  cp(biscuitJs, join(vendorDir, 'biscuit_bg.js')),
  cp(biscuitWasm, join(vendorDir, 'biscuit_bg.wasm')),
])

function run(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: 'inherit',
      env: process.env,
    })

    child.on('exit', code => {
      if (code === 0) {
        resolve()
        return
      }
      reject(new Error(`${command} ${args.join(' ')} exited with code ${code ?? 'null'}`))
    })
    child.on('error', reject)
  })
}
