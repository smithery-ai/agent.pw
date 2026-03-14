import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { resolveLocalDaemonRunnerFrom } from '../packages/cli/src/local/server-runtime'

const tempDirs: string[] = []

function createTempDir(prefix: string) {
  const dir = join(tmpdir(), `${prefix}-${Math.random().toString(36).slice(2, 10)}`)
  mkdirSync(dir, { recursive: true })
  tempDirs.push(dir)
  return dir
}

afterEach(() => {
  tempDirs.splice(0).forEach(dir => {
    rmSync(dir, { recursive: true, force: true })
  })
})

describe('CLI local daemon resolution', () => {
  it('prefers the bundled local daemon when dist output is present', () => {
    const packageDir = createTempDir('agentpw-cli')
    const distDir = join(packageDir, 'dist')
    mkdirSync(distDir, { recursive: true })
    writeFileSync(join(distDir, 'index.js'), '// cli\n')
    writeFileSync(join(distDir, 'local-daemon.js'), '// daemon\n')

    const runner = resolveLocalDaemonRunnerFrom(join(distDir, 'index.js'), packageDir)

    expect(runner.source).toBe('bundle')
    expect(runner.command).toBe(process.execPath)
    expect(runner.args).toEqual([join(distDir, 'local-daemon.js')])
    expect(runner.displayPath).toBe(join(distDir, 'local-daemon.js'))
  })

  it('falls back to the source-checkout daemon when tsx is available', () => {
    const repoRoot = createTempDir('agentpw-repo')
    const serverRuntimeDir = join(repoRoot, 'packages', 'cli', 'src', 'local')
    const sourceDir = join(repoRoot, 'packages', 'cli', 'src')
    const nodeBinDir = join(repoRoot, 'node_modules', '.bin')

    mkdirSync(serverRuntimeDir, { recursive: true })
    mkdirSync(nodeBinDir, { recursive: true })
    writeFileSync(join(sourceDir, 'local-daemon.ts'), '// daemon source\n')
    writeFileSync(join(nodeBinDir, process.platform === 'win32' ? 'tsx.cmd' : 'tsx'), '')

    const runner = resolveLocalDaemonRunnerFrom(
      join(serverRuntimeDir, 'server-runtime.ts'),
      repoRoot,
    )

    expect(runner.source).toBe('source')
    expect(runner.command).toBe(process.execPath)
    expect(runner.args).toEqual([
      '--no-warnings=ExperimentalWarning',
      '--loader',
      'tsx',
      join(sourceDir, 'local-daemon.ts'),
    ])
    expect(runner.cwd).toBe(repoRoot)
    expect(runner.displayPath).toBe(join(sourceDir, 'local-daemon.ts'))
  })
})
