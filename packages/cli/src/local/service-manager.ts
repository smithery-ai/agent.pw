import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { LocalAgentPwPaths } from '../../../server/src/local/config'
import {
  buildLocalBaseUrl,
  ensureLocalAgentPwDirs,
  isProcessAlive,
  localAgentPwPaths,
  readLocalConfig,
  readLocalPid,
  removeLocalPid,
} from '../../../server/src/local/config'
import { probeLocalServer, type LocalDaemonRunner } from './server-runtime'

type LocalServiceKind = 'launchd' | 'systemd'

interface LocalServiceDefinition {
  kind: LocalServiceKind
  label: string
  filePath: string
}

export interface LocalServiceStatus {
  supported: boolean
  installed: boolean
  running: boolean
  kind: LocalServiceKind | null
  label: string | null
  filePath: string | null
  pid: number | null
}

export interface UnmanagedLocalServer {
  baseUrl: string
  pids: number[]
}

const LAUNCHD_LABEL = 'ai.agentpw.daemon'
const SYSTEMD_UNIT = 'agentpw.service'

function unsupportedServiceMessage() {
  return 'Persistent local installs are currently supported on macOS (launchd) and Linux (systemd user services).'
}

function resolveServiceDir(kind: LocalServiceKind) {
  const overridden = process.env.AGENTPW_SERVICE_DIR?.trim()
  if (overridden) {
    return overridden
  }

  if (kind === 'launchd') {
    return join(homedir(), 'Library', 'LaunchAgents')
  }

  return join(homedir(), '.config', 'systemd', 'user')
}

function resolveServiceDefinition(): LocalServiceDefinition | null {
  if (process.platform === 'darwin') {
    return {
      kind: 'launchd',
      label: LAUNCHD_LABEL,
      filePath: join(resolveServiceDir('launchd'), `${LAUNCHD_LABEL}.plist`),
    }
  }

  if (process.platform === 'linux') {
    return {
      kind: 'systemd',
      label: SYSTEMD_UNIT,
      filePath: join(resolveServiceDir('systemd'), SYSTEMD_UNIT),
    }
  }

  return null
}

function escapeXml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function quoteSystemd(value: string) {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function writeLaunchdPlist(
  runner: LocalDaemonRunner,
  paths: LocalAgentPwPaths,
  definition: LocalServiceDefinition,
) {
  const programArguments = [...runner.args, 'serve']
    .map(arg => `    <string>${escapeXml(arg)}</string>`)
    .join('\n')
  const environmentVariables = [
    '    <key>AGENTPW_HOME</key>',
    `    <string>${escapeXml(paths.homeDir)}</string>`,
  ].join('\n')
  const workingDirectory = runner.cwd
    ? [
      '  <key>WorkingDirectory</key>',
      `  <string>${escapeXml(runner.cwd)}</string>`,
    ].join('\n')
    : ''

  mkdirSync(resolveServiceDir('launchd'), { recursive: true })
  writeFileSync(definition.filePath, [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    '  <key>Label</key>',
    `  <string>${escapeXml(definition.label)}</string>`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    `    <string>${escapeXml(runner.command)}</string>`,
    programArguments,
    '  </array>',
    '  <key>RunAtLoad</key>',
    '  <true/>',
    '  <key>KeepAlive</key>',
    '  <true/>',
    workingDirectory,
    '  <key>EnvironmentVariables</key>',
    '  <dict>',
    environmentVariables,
    '  </dict>',
    '  <key>StandardOutPath</key>',
    `  <string>${escapeXml(paths.logFile)}</string>`,
    '  <key>StandardErrorPath</key>',
    `  <string>${escapeXml(paths.logFile)}</string>`,
    '</dict>',
    '</plist>',
    '',
  ].filter(Boolean).join('\n'))
}

function writeSystemdUnit(
  runner: LocalDaemonRunner,
  paths: LocalAgentPwPaths,
  definition: LocalServiceDefinition,
) {
  mkdirSync(resolveServiceDir('systemd'), { recursive: true })
  const execStart = [runner.command, ...runner.args, 'serve']
    .map(quoteSystemd)
    .join(' ')
  const workingDirectory = runner.cwd
    ? `WorkingDirectory=${quoteSystemd(runner.cwd)}`
    : null

  writeFileSync(definition.filePath, [
    '[Unit]',
    'Description=agent.pw local daemon',
    'After=network.target',
    '',
    '[Service]',
    'Type=simple',
    `ExecStart=${execStart}`,
    `Environment=${quoteSystemd(`AGENTPW_HOME=${paths.homeDir}`)}`,
    workingDirectory,
    'Restart=always',
    'RestartSec=2',
    `StandardOutput=append:${paths.logFile}`,
    `StandardError=append:${paths.logFile}`,
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].filter(Boolean).join('\n'))
}

function runServiceCommand(command: string, args: string[], allowFailure = false) {
  try {
    execFileSync(command, args, { stdio: 'ignore' })
  } catch (error) {
    if (allowFailure) {
      return
    }

    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`${command} ${args.join(' ')} failed: ${message}`)
  }
}

function readServiceCommandOutput(command: string, args: string[]) {
  try {
    const output = execFileSync(command, args, {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    })
    return typeof output === 'string' ? output.trim() : String(output ?? '').trim()
  } catch {
    return null
  }
}

function readLaunchdPid(label: string) {
  const uid = process.getuid?.()
  if (uid == null) {
    return null
  }

  const output = readServiceCommandOutput('launchctl', ['print', `gui/${uid}/${label}`])
  if (!output) {
    return null
  }

  const match = output.match(/\bpid = (\d+)/)
  if (!match) {
    return null
  }

  const pid = Number.parseInt(match[1], 10)
  return Number.isInteger(pid) && pid > 0 ? pid : null
}

function readSystemdPid() {
  const output = readServiceCommandOutput(
    'systemctl',
    ['--user', 'show', SYSTEMD_UNIT, '--property', 'MainPID', '--value'],
  )
  if (!output) {
    return null
  }

  const pid = Number.parseInt(output, 10)
  return Number.isInteger(pid) && pid > 0 ? pid : null
}

function readManagedServicePid(definition: LocalServiceDefinition) {
  if (definition.kind === 'launchd') {
    return readLaunchdPid(definition.label)
  }

  return readSystemdPid()
}

function listListeningProcessIds(port: number) {
  const output = readServiceCommandOutput(
    'lsof',
    ['-nP', '-tiTCP:%s'.replace('%s', String(port)), '-sTCP:LISTEN'],
  )
  if (!output) {
    return []
  }

  return output
    .split(/\r?\n/)
    .map(line => Number.parseInt(line.trim(), 10))
    .filter(pid => Number.isInteger(pid) && pid > 0)
}

async function waitForPortToClose(baseUrl: string, timeoutMs = 5_000, intervalMs = 200) {
  const startedAt = Date.now()

  while (Date.now() - startedAt < timeoutMs) {
    if (!(await probeLocalServer(baseUrl))) {
      return
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for ${baseUrl} to stop responding.`)
}

async function waitForManagedService(
  baseUrl: string,
  paths: LocalAgentPwPaths,
  timeoutMs = 15_000,
  intervalMs = 250,
) {
  const startedAt = Date.now()

  while (Date.now() - startedAt < timeoutMs) {
    const localPid = readLocalPid(paths)
    if (localPid && isProcessAlive(localPid) && (await probeLocalServer(baseUrl))) {
      return localPid
    }

    await new Promise(resolve => setTimeout(resolve, intervalMs))
  }

  throw new Error(`Timed out waiting for agent.pw at ${baseUrl}. Check ${paths.logFile}.`)
}

function installLaunchdService(
  runner: LocalDaemonRunner,
  paths: LocalAgentPwPaths,
  definition: LocalServiceDefinition,
) {
  const uid = process.getuid?.()
  if (uid == null) {
    throw new Error('launchd installs require a real user session.')
  }

  writeLaunchdPlist(runner, paths, definition)
  runServiceCommand('launchctl', ['bootout', `gui/${uid}/${definition.label}`], true)
  runServiceCommand('launchctl', ['bootstrap', `gui/${uid}`, definition.filePath])
  runServiceCommand('launchctl', ['kickstart', '-k', `gui/${uid}/${definition.label}`])
}

function installSystemdService(
  runner: LocalDaemonRunner,
  paths: LocalAgentPwPaths,
  definition: LocalServiceDefinition,
  existed: boolean,
) {
  writeSystemdUnit(runner, paths, definition)
  runServiceCommand('systemctl', ['--user', 'daemon-reload'])
  runServiceCommand('systemctl', ['--user', 'enable', SYSTEMD_UNIT], true)
  if (existed) {
    runServiceCommand('systemctl', ['--user', 'restart', SYSTEMD_UNIT])
    return
  }

  runServiceCommand('systemctl', ['--user', 'enable', '--now', SYSTEMD_UNIT])
}

export function describeLocalService(): LocalServiceStatus {
  const definition = resolveServiceDefinition()
  if (!definition) {
    return {
      supported: false,
      installed: false,
      running: false,
      kind: null,
      label: null,
      filePath: null,
      pid: null,
    }
  }

  const installed = existsSync(definition.filePath)
  const pid = installed ? readManagedServicePid(definition) : null

  return {
    supported: true,
    installed,
    running: pid !== null,
    kind: definition.kind,
    label: definition.label,
    filePath: definition.filePath,
    pid,
  }
}

export async function detectUnmanagedLocalServer(
  paths = localAgentPwPaths(),
): Promise<UnmanagedLocalServer | null> {
  const config = readLocalConfig(paths)
  if (!config) {
    return null
  }

  const service = describeLocalService()
  if (service.installed && service.running) {
    return null
  }

  const baseUrl = buildLocalBaseUrl(config.port)
  if (!(await probeLocalServer(baseUrl))) {
    return null
  }

  return {
    baseUrl,
    pids: listListeningProcessIds(config.port),
  }
}

export async function stopUnmanagedLocalServer(
  server: UnmanagedLocalServer,
) {
  if (server.pids.length === 0) {
    throw new Error(
      `A process is already responding at ${server.baseUrl}, but its PID could not be determined. Stop it manually and rerun \`npx agent.pw start\`.`,
    )
  }

  for (const pid of server.pids) {
    try {
      process.kill(pid, 'SIGTERM')
    } catch {
      // Ignore already-exited processes and wait for the port probe below.
    }
  }

  await waitForPortToClose(server.baseUrl)
}

export async function ensureLocalService(
  runner: LocalDaemonRunner,
  paths = localAgentPwPaths(),
) {
  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('agent.pw is not configured. Run `npx agent.pw start` first.')
  }

  const definition = resolveServiceDefinition()
  if (!definition) {
    throw new Error(unsupportedServiceMessage())
  }

  const baseUrl = buildLocalBaseUrl(config.port)
  const existed = existsSync(definition.filePath)
  if (existed && (await probeLocalServer(baseUrl))) {
    return {
      changed: false,
      baseUrl,
      logFile: paths.logFile,
      servicePath: definition.filePath,
      kind: definition.kind,
    }
  }

  ensureLocalAgentPwDirs(paths)
  if (definition.kind === 'launchd') {
    installLaunchdService(runner, paths, definition)
  } else {
    installSystemdService(runner, paths, definition, existed)
  }

  await waitForManagedService(baseUrl, paths)

  return {
    changed: true,
    baseUrl,
    logFile: paths.logFile,
    servicePath: definition.filePath,
    kind: definition.kind,
  }
}

export function stopLocalService(paths = localAgentPwPaths()) {
  const definition = resolveServiceDefinition()
  if (!definition) {
    throw new Error(unsupportedServiceMessage())
  }

  const existed = existsSync(definition.filePath)
  if (!existed) {
    return false
  }

  if (definition.kind === 'launchd') {
    const uid = process.getuid?.()
    if (uid == null) {
      throw new Error('launchd installs require a real user session.')
    }

    runServiceCommand('launchctl', ['bootout', `gui/${uid}/${definition.label}`], true)
  } else {
    runServiceCommand('systemctl', ['--user', 'disable', '--now', SYSTEMD_UNIT], true)
    runServiceCommand('systemctl', ['--user', 'daemon-reload'], true)
  }

  rmSync(definition.filePath, { force: true })
  removeLocalPid(paths)
  return true
}
