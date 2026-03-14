import { cp, mkdir, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const packageDir = dirname(__dirname)
const distDir = join(packageDir, 'dist')
const biscuitVendorDir = join(distDir, 'vendor', 'biscuit-wasm')
const biscuitRuntimePackageDir = join(distDir, 'node_modules', '@biscuit-auth', 'biscuit-wasm')
const pgliteVendorDir = join(distDir, 'vendor', 'pglite')

const require = createRequire(import.meta.url)
const smitheryShim = require.resolve('@smithery/biscuit/shim')
const smitheryRequire = createRequire(smitheryShim)
const biscuitJs = smitheryRequire.resolve('@biscuit-auth/biscuit-wasm/module/biscuit_bg.js')
const biscuitWasm = smitheryRequire.resolve('@biscuit-auth/biscuit-wasm/module/biscuit_bg.wasm')
const biscuitPackageDir = dirname(dirname(biscuitJs))
const pgliteEntry = require.resolve('@electric-sql/pglite')
const pgliteDir = dirname(pgliteEntry)
const pgliteData = join(pgliteDir, 'postgres.data')
const pgliteWasm = join(pgliteDir, 'postgres.wasm')

await rm(distDir, { recursive: true, force: true })
await run('bun', [
  'build',
  'src/index.ts',
  'src/local-daemon.ts',
  '--outdir',
  'dist',
  '--target',
  'node',
  '--format',
  'esm',
  '--banner',
  '#!/usr/bin/env node',
], packageDir)
await mkdir(biscuitVendorDir, { recursive: true })
await mkdir(dirname(biscuitRuntimePackageDir), { recursive: true })
await mkdir(pgliteVendorDir, { recursive: true })
await Promise.all([
  cp(biscuitJs, join(biscuitVendorDir, 'biscuit_bg.js')),
  cp(biscuitWasm, join(biscuitVendorDir, 'biscuit_bg.wasm')),
  cp(biscuitPackageDir, biscuitRuntimePackageDir, { recursive: true }),
  cp(pgliteData, join(pgliteVendorDir, 'postgres.data')),
  cp(pgliteWasm, join(pgliteVendorDir, 'postgres.wasm')),
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
