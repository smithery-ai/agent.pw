/// <reference lib="webworker" />
/**
 * Node.js shim for @biscuit-auth/biscuit-wasm.
 *
 * The upstream package targets bundler (wasm-pack --target bundler), which
 * expects the bundler to handle WASM import. Node.js doesn't support
 * `import ... from "*.wasm"` natively, so we load the WASM file manually
 * and wire it into the JS glue code.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'

// Walk up from this file to find node_modules
const thisDir = dirname(fileURLToPath(import.meta.url))
const projectRoot = join(thisDir, '..')
const moduleDir = join(projectRoot, 'node_modules', '@biscuit-auth', 'biscuit-wasm', 'module')
const bgJsPath = join(moduleDir, 'biscuit_bg.js')
const wasmPath = join(moduleDir, 'biscuit_bg.wasm')

// Load the glue code via file:// URL to bypass package exports map
const bg: Record<string, any> = await import(pathToFileURL(bgJsPath).href)

// Load and compile WASM synchronously
const wasmBytes = readFileSync(wasmPath)
const wasmModule = new WebAssembly.Module(wasmBytes)

// Build imports for the WASM instance
const wasmImports: Record<string, unknown> = {}
for (const [key, value] of Object.entries(bg)) {
  if (key.startsWith('__wbg_') || key.startsWith('__wbindgen_')) {
    wasmImports[key] = value
  }
}

const snippetExports = { performance_now: () => performance.now() }
const imports: Record<string, Record<string, unknown>> = {
  './biscuit_bg.js': wasmImports,
}

// Discover snippet module paths from WASM imports
for (const imp of WebAssembly.Module.imports(wasmModule)) {
  if (imp.module.includes('snippets/')) {
    imports[imp.module] = snippetExports
  }
}

const instance = new WebAssembly.Instance(wasmModule, imports as WebAssembly.Imports)
bg.__wbg_set_wasm(instance.exports)

const start = instance.exports.__wbindgen_start as () => void
start()

export const Biscuit = bg.Biscuit
export const BiscuitBuilder = bg.BiscuitBuilder
export const BlockBuilder = bg.BlockBuilder
export const KeyPair = bg.KeyPair
export const PrivateKey = bg.PrivateKey
export const PublicKey = bg.PublicKey
export const AuthorizerBuilder = bg.AuthorizerBuilder
export const SignatureAlgorithm = bg.SignatureAlgorithm
export const Fact = bg.Fact
export const Rule = bg.Rule
export const Check = bg.Check
export const Policy = bg.Policy
