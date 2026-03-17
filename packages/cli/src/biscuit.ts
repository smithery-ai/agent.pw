import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'

import type {
  Biscuit as BiscuitClass,
  PublicKey as PublicKeyClass,
  SignatureAlgorithm as SignatureAlgorithmEnum,
} from '@smithery/biscuit'
import { isRecord } from './type-utils'

type BiscuitModule = {
  Biscuit: typeof BiscuitClass
  PublicKey: typeof PublicKeyClass
  SignatureAlgorithm: typeof SignatureAlgorithmEnum
}

type WasmGlueModule = BiscuitModule & {
  __wbg_set_wasm(wasm: WebAssembly.Instance['exports']): void
}

type WasmImports = NonNullable<ConstructorParameters<typeof WebAssembly.Instance>[1]>
type WasmModuleImports = WasmImports[string]

const SNIPPET_MODULES = [
  './snippets/biscuit-auth-1c48f52e9814dd36/inline0.js',
  './snippets/biscuit-auth-314ca57174ae0e6d/inline0.js',
  './snippets/biscuit-auth-4a94c16b4e5134af/inline0.js',
  './snippets/biscuit-auth-9839c5a0e8279f50/inline0.js',
  './snippets/biscuit-auth-da0d0cfccbdf8dc5/inline0.js',
  './snippets/biscuit-auth-e52d23e03c1c6188/inline0.js',
  './snippets/biscuit-auth-e5319c95bbe1e260/inline0.js',
]

let biscuitModulePromise: Promise<BiscuitModule> | undefined

export function loadBiscuit() {
  biscuitModulePromise ??= initBiscuit()
  return biscuitModulePromise
}

async function initBiscuit(): Promise<BiscuitModule> {
  const wasmUrl = getAssetUrl('biscuit_bg.wasm')
  const wasmModule = new WebAssembly.Module(readFileSync(wasmUrl))

  const importedBg = await import(getAssetUrl('biscuit_bg.js').href)
  if (!isWasmGlueModule(importedBg)) {
    throw new Error('Failed to load Biscuit WASM glue module')
  }
  const bg = importedBg

  const wasmImports: WasmModuleImports = {}
  for (const [key, value] of Object.entries(bg)) {
    if (key.startsWith('__wbg_') || key.startsWith('__wbindgen_')) {
      wasmImports[key] = value
    }
  }

  const snippetExports = { performance_now: () => performance.now() }
  const imports: WasmImports = { './biscuit_bg.js': wasmImports }

  for (const moduleName of SNIPPET_MODULES) {
    imports[moduleName] = snippetExports
  }

  const instance = new WebAssembly.Instance(wasmModule, imports)
  bg.__wbg_set_wasm(instance.exports)

  const start = instance.exports.__wbindgen_start
  if (typeof start === 'function') {
    start()
  }

  return {
    Biscuit: bg.Biscuit,
    PublicKey: bg.PublicKey,
    SignatureAlgorithm: bg.SignatureAlgorithm,
  }
}

function getAssetUrl(fileName: string) {
  if (import.meta.url.includes('/$bunfs/')) {
    return pathToFileURL(join(dirname(process.execPath), 'vendor', 'biscuit-wasm', fileName))
  }

  return new URL(`./vendor/biscuit-wasm/${fileName}`, import.meta.url)
}

function isWasmGlueModule(value: unknown): value is WasmGlueModule {
  return isRecord(value)
    && typeof value.Biscuit === 'function'
    && typeof value.PublicKey === 'function'
    && typeof value.SignatureAlgorithm === 'object'
    && typeof value.__wbg_set_wasm === 'function'
}
