import { localAgentPwPaths, readLocalConfig } from '../../../server/src/local/config'
import { ensureLocalCliConfig } from '../config'
import {
  buildVaultLaunchUrl,
  describeLocalServer,
  readLocalServerLogs,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
} from '../local/server-runtime'
import {
  detectUnmanagedLocalServer,
  ensureLocalService,
  stopLocalService,
  stopUnmanagedLocalServer,
} from '../local/service-manager'
import {
  confirmAgentPwSkillInstall,
  confirmTakeoverRunningProcess,
  installAgentPwSkill,
  openBrowser,
  printAgentPwSkillInstallHint,
  printBinarySource,
  printOnboardingHeader,
  printOnboardingSuccess,
} from '../local/onboarding'

interface StartOptions {
  noBrowser?: boolean
}

export async function start(options: StartOptions = {}) {
  const { noBrowser = false } = options
  const paths = localAgentPwPaths()

  printOnboardingHeader()

  const daemon = resolveLocalDaemonRunner()
  printBinarySource(daemon.source, daemon.displayPath)

  await runLocalServerDaemonCommand(daemon, ['setup'], paths)

  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('Local agent.pw setup did not produce a config file.')
  }

  const unmanaged = await detectUnmanagedLocalServer(paths)
  if (unmanaged) {
    const confirmed = await confirmTakeoverRunningProcess(unmanaged.baseUrl)
    if (!confirmed) {
      throw new Error(
        `A process is already responding at ${unmanaged.baseUrl}. Stop it manually or rerun interactively to let agent.pw take over.`,
      )
    }

    await stopUnmanagedLocalServer(unmanaged)
  }

  const service = await ensureLocalService(daemon, paths)
  ensureLocalCliConfig(config, paths)

  console.log(`Server: ${paths.configFile}`)
  console.log(`CLI:    ${paths.cliConfigFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    ${service.baseUrl}`)
  console.log(`Local service is running at ${service.baseUrl}`)
  console.log(`Service: ${service.kind} (${service.servicePath})`)

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
  const vaultUrl = buildVaultLaunchUrl(service.baseUrl, bootstrapToken)

  const browserOpened = !noBrowser && openBrowser(vaultUrl)
  printOnboardingSuccess(vaultUrl, browserOpened)
}

export function stopCmd() {
  const paths = localAgentPwPaths()
  const config = readLocalConfig(paths)
  const stopped = stopLocalService()
  if (!stopped) {
    console.log('agent.pw is already stopped.')
    return
  }

  console.log('Stopped the local agent.pw service.')
  if (config) {
    console.log(`Data remains at ${config.dataDir}.`)
  }
}

export async function logsCmd(tail = 200) {
  const status = describeLocalServer()
  const logs = await readLocalServerLogs(undefined, tail)

  if (!logs) {
    console.log(`No service logs found at ${status.logFile}.`)
    return
  }

  console.log(logs)
}
