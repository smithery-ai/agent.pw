import { localAgentPwPaths, readLocalConfig } from '../../../server/src/local/config'
import {
  buildVaultLaunchUrl,
  describeLocalServer,
  readLocalServerLogs,
  resolveLocalDaemonRunner,
  runLocalServerDaemonCommand,
} from '../local/server-runtime'
import { ensureLocalService, uninstallLocalService } from '../local/service-manager'
import {
  confirmAgentPwSkillInstall,
  installAgentPwSkill,
  openBrowser,
  printAgentPwSkillInstallHint,
  printBinarySource,
  printOnboardingHeader,
  printOnboardingSuccess,
} from '../local/onboarding'

interface InstallOptions {
  noBrowser?: boolean
}

export async function install(options: InstallOptions = {}) {
  const { noBrowser = false } = options
  const paths = localAgentPwPaths()

  printOnboardingHeader()

  const daemon = resolveLocalDaemonRunner()
  printBinarySource(daemon.source, daemon.displayPath)

  await runLocalServerDaemonCommand(daemon, ['install'], paths)

  const config = readLocalConfig(paths)
  if (!config) {
    throw new Error('Local agent.pw setup did not produce a config file.')
  }

  console.log(`Config: ${paths.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    http://127.0.0.1:${config.port}`)

  const service = await ensureLocalService(daemon, paths)
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

export function uninstallCmd() {
  const paths = localAgentPwPaths()
  const config = readLocalConfig(paths)
  const stopped = uninstallLocalService()
  if (!stopped) {
    console.log('agent.pw is not installed.')
    return
  }

  console.log('Removed the local agent.pw service.')
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
