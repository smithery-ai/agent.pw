/**
 * CF Workers shim for @biscuit-auth/biscuit-wasm.
 *
 * The upstream package targets bundler (wasm-pack --target bundler), which
 * expects the bundler to handle WASM instantiation. CF Workers import .wasm
 * files as pre-compiled WebAssembly.Module objects instead, so we manually
 * instantiate the module and wire it up to the JS glue code.
 *
 * We use direct relative paths into node_modules so both wrangler (deploy)
 * and @cloudflare/vitest-pool-workers (test) can resolve them.
 */

// @ts-nocheck — wasm-bindgen glue has no TS types

// CF Workers: importing a .wasm gives us a WebAssembly.Module
// Use a path wrangler can resolve (it follows filesystem paths, not package exports)
import wasmModule from "../node_modules/@biscuit-auth/biscuit-wasm/module/biscuit_bg.wasm"
import * as bg from "../node_modules/@biscuit-auth/biscuit-wasm/module/biscuit_bg.js"

const wasmImports: Record<string, unknown> = {}
for (const [key, value] of Object.entries(bg)) {
	if (key.startsWith("__wbg_") || key.startsWith("__wbindgen_")) {
		wasmImports[key] = value
	}
}

const snippetExports = { performance_now: () => performance.now() }
const snippetModules = [
	"./snippets/biscuit-auth-1c48f52e9814dd36/inline0.js",
	"./snippets/biscuit-auth-314ca57174ae0e6d/inline0.js",
	"./snippets/biscuit-auth-4a94c16b4e5134af/inline0.js",
	"./snippets/biscuit-auth-9839c5a0e8279f50/inline0.js",
	"./snippets/biscuit-auth-da0d0cfccbdf8dc5/inline0.js",
	"./snippets/biscuit-auth-e52d23e03c1c6188/inline0.js",
	"./snippets/biscuit-auth-e5319c95bbe1e260/inline0.js",
]

const imports: Record<string, Record<string, unknown>> = {
	"./biscuit_bg.js": wasmImports,
}
for (const path of snippetModules) {
	imports[path] = snippetExports
}

const instance = new WebAssembly.Instance(wasmModule, imports)
bg.__wbg_set_wasm(instance.exports)

const start = instance.exports.__wbindgen_start as () => void
start()

export {
	Biscuit,
	BiscuitBuilder,
	BlockBuilder,
	KeyPair,
	PrivateKey,
	PublicKey,
	AuthorizerBuilder,
	SignatureAlgorithm,
	Fact,
	Rule,
	Check,
	Policy,
} from "../node_modules/@biscuit-auth/biscuit-wasm/module/biscuit_bg.js"
