import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const versionFlagIndex = process.argv.indexOf('--version')
if (versionFlagIndex === -1 || !process.argv[versionFlagIndex + 1]) {
  throw new Error('Usage: node packages/cli/scripts/generate-server-binary-manifest.mjs --version <version> --asset <platform-arch=path> [...]')
}

const version = process.argv[versionFlagIndex + 1]
const assetArgs = []

for (let index = 0; index < process.argv.length; index++) {
  if (process.argv[index] === '--asset' && process.argv[index + 1]) {
    assetArgs.push(process.argv[index + 1])
  }
}

if (assetArgs.length === 0) {
  throw new Error('At least one --asset <platform-arch=path> entry is required.')
}

const entries = await Promise.all(assetArgs.map(async arg => {
  const separatorIndex = arg.indexOf('=')
  if (separatorIndex === -1) {
    throw new Error(`Invalid asset mapping: ${arg}`)
  }

  const key = arg.slice(0, separatorIndex)
  const filePath = resolve(arg.slice(separatorIndex + 1))
  const fileName = filePath.split(/[\\/]/).at(-1)

  if (!fileName) {
    throw new Error(`Invalid asset path: ${arg}`)
  }

  const contents = await readFile(filePath)
  const sha256 = createHash('sha256').update(contents).digest('hex')

  return {
    key,
    fileName,
    sha256,
  }
}))

const lines = [
  'export interface ServerBinaryAsset {',
  '  fileName: string',
  '  url: string',
  '  sha256: string',
  '}',
  '',
  `const versionTag = 'agent.pw-v${version}'`,
  "const baseUrl = `https://github.com/smithery-ai/agent.pw/releases/download/${versionTag}`",
  '',
  'export const SERVER_BINARY_MANIFEST: Record<string, ServerBinaryAsset> = {',
  ...entries.map(entry => `  '${entry.key}': { fileName: '${entry.fileName}', url: \`\${baseUrl}/${entry.fileName}\`, sha256: '${entry.sha256}' },`),
  '}',
  '',
]

await writeFile(
  resolve('packages/cli/src/local/server-binary-manifest.generated.ts'),
  `${lines.join('\n')}`,
)
