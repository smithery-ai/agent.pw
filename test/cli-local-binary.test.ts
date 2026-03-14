import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

const tempDirs: string[] = []
const originalCwd = process.cwd()

function createTempDir(prefix: string) {
  const dir = join(tmpdir(), `${prefix}-${Math.random().toString(36).slice(2, 10)}`)
  mkdirSync(dir, { recursive: true })
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.resetModules()
  vi.unstubAllEnvs()
  process.chdir(originalCwd)

  tempDirs.splice(0).forEach(dir => {
    rmSync(dir, { recursive: true, force: true })
  })
})

describe('CLI local server binary resolution', () => {
  it('builds the local server binary from a source checkout when release checksums are unresolved', async () => {
    const homeDir = createTempDir('agentpw-home')
    const repoRoot = createTempDir('agentpw-repo')
    const cliDir = join(repoRoot, 'packages', 'cli')

    mkdirSync(cliDir, { recursive: true })
    mkdirSync(join(repoRoot, 'packages', 'server'), { recursive: true })
    mkdirSync(join(repoRoot, 'scripts'), { recursive: true })
    writeFileSync(join(repoRoot, 'packages', 'server', 'entry.local.ts'), '// test marker\n')
    writeFileSync(join(repoRoot, 'scripts', 'build-local-server-binary.mjs'), '// test marker\n')

    process.chdir(cliDir)
    vi.stubEnv('AGENTPW_HOME', homeDir)

    const manifestKey = `${process.platform}-${process.arch}`
    vi.doMock('../packages/cli/src/local/server-binary-manifest.generated', () => ({
      SERVER_BINARY_MANIFEST: {
        [manifestKey]: {
          fileName: `agentpw-local-server-${manifestKey}`,
          url: 'https://example.invalid/agentpw-local-server',
          sha256: '__GENERATED_AT_RELEASE__',
        },
      },
    }))

    vi.doMock('node:child_process', () => ({
      spawn: vi.fn(),
      spawnSync: vi.fn(() => ({ status: 0 })),
    }))

    const runtime = await import('../packages/cli/src/local/server-runtime')
    const config = await import('../packages/server/src/local/config')

    const result = await runtime.ensureLocalServerBinary(config.localAgentPwPaths(homeDir))

    expect(result.source).toBe('source')
    expect(existsSync(result.binaryPath)).toBe(true)
    const runner = readFileSync(result.binaryPath, 'utf8')
    expect(runner).toContain('packages/server/entry.local.ts')
    expect(runner).toContain('bun ')
  })
})
