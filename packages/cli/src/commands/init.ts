import { localAgentPwPaths, readLocalConfig } from '../../../server/src/local/config'
import {
  buildVaultLaunchUrl,
  describeLocalServer,
  printServerSummary,
  readLocalServerLogs,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
  startLocalServerDaemon,
  stopLocalServerDaemon,
} from '../local/server-runtime'
import {
  confirmAgentPwSkillInstall,
  installAgentPwSkill,
  openBrowser,
  printAgentPwSkillInstallHint,
  printBinarySource,
  printOnboardingHeader,
  printOnboardingSuccess,
} from '../local/onboarding'

interface InitOptions {
  noBrowser?: boolean
}

export async function init(options: InitOptions = {}) {
  const { noBrowser = false } = options
  const paths = localAgentPwPaths()

  printOnboardingHeader()

  const daemon = resolveLocalDaemonRunner()
  printBinarySource(daemon.source, daemon.displayPath)

  await runLocalServerDaemonCommand(daemon, ['init'], paths)

  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('Local agent.pw setup did not produce a config file.')
  }

  console.log(`Config: ${paths.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    http://127.0.0.1:${config.port}`)

  const server = await startLocalServerDaemon(daemon, paths)
  console.log(server.started ? `Started local server at ${server.baseUrl}` : `Local server already running at ${server.baseUrl}`)

  const shouldInstallSkill = await confirmAgentPwSkillInstall()
  if (shouldInstallSkill) {
    console.log('Installing the Smithery skill...')
    try {
      installAgentPwSkill()
    } catch {
      console.error('')
      console.error('Failed to install the Smithery skill automatically.')
      printAgentPwSkillInstallHint()
    }
  } else {
    printAgentPwSkillInstallHint()
  }

  const bootstrapToken = await runLocalServerDaemonCommand(
    daemon,
    ['bootstrap-token', '--ttl', '10m'],
    paths,
  )
  const vaultUrl = buildVaultLaunchUrl(server.baseUrl, bootstrapToken)

  const browserOpened = !noBrowser && openBrowser(vaultUrl)
  printOnboardingSuccess(vaultUrl, browserOpened)
}

export async function startServerCmd() {
  const paths = localAgentPwPaths()
  const daemon = resolveLocalDaemonRunner()
  await runLocalServerDaemonCommand(daemon, ['init'], paths)
  const server = await startLocalServerDaemon(daemon, paths)

  if (server.started) {
    console.log(`Started agent.pw at ${server.baseUrl}`)
    console.log(`Logs: ${server.logFile}`)
    return
  }

  console.log(`agent.pw is already running at ${server.baseUrl}`)
}

export function stopServerCmd() {
  const stopped = stopLocalServerDaemon()
  if (!stopped) {
    console.log('agent.pw is not running.')
    return
  }

  console.log('Stopped local agent.pw server.')
}

export function statusServerCmd() {
  printServerSummary()
}

export async function logsServerCmd(tail = 200) {
  const status = describeLocalServer()
  const logs = await readLocalServerLogs(undefined, tail)

  if (!logs) {
    console.log(`No server logs found at ${status.logFile}.`)
    return
  }

  console.log(logs)
}
