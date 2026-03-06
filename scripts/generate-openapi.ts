/**
 * Offline OpenAPI spec generation script.
 *
 * Generates the OpenAPI spec by importing the Hono app and using
 * hono-openapi's route introspection. No HTTP server is started.
 *
 * Usage: pnpm run openapi:generate
 * Output: openapi.json in the repo root
 */
import { writeFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateSpecs } from 'hono-openapi'
import { injectSchemas } from '../src/lib/openapi-utils'
import { createCoreApp } from '../src/core/app'
import { openAPIDocumentation, allSchemas } from '../src/openapi'

const __dirname = dirname(fileURLToPath(import.meta.url))

async function main() {
  console.log('Generating OpenAPI spec...')

  // Create a bare core app for route introspection (no DB or keys needed)
  const app = createCoreApp()

  const spec = await generateSpecs(app, {
    documentation: openAPIDocumentation,
  })

  const result = { ...spec } as Record<string, unknown>

  injectSchemas(result, allSchemas)

  const outputPath = resolve(__dirname, '..', 'openapi.json')
  writeFileSync(outputPath, JSON.stringify(result, null, 2))

  const pathCount = Object.keys((result.paths as Record<string, unknown>) ?? {}).length
  console.log(`OpenAPI spec generated: ${outputPath} (${pathCount} paths)`)
}

main().catch(err => {
  console.error('Failed to generate OpenAPI spec:', err)
  process.exit(1)
})
