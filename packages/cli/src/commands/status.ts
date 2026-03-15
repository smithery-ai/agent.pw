import { readLocalConfig } from '../../../server/src/local/config'
import { describeLocalService } from '../local/service-manager'
import { describeLocalServer, probeLocalServer } from '../local/server-runtime'

function printUnconfigured() {
  console.log('No agent.pw instance is configured.')
  console.log('Run `npx agent.pw start` to create and start a local instance.')
  console.log('Or set AGENT_PW_HOST and AGENT_PW_TOKEN for a remote self-hosted deployment.')
}

export async function statusCmd() {
  const envHost = process.env.AGENT_PW_HOST?.trim()
  const envToken = process.env.AGENT_PW_TOKEN?.trim()

  if (envHost || envToken) {
    if (!(envHost && envToken)) {
      console.log('Remote agent.pw configuration is incomplete.')
      if (!envHost) {
        console.log('Missing: AGENT_PW_HOST')
      }
      if (!envToken) {
        console.log('Missing: AGENT_PW_TOKEN')
      }
      return
    }

    const url = envHost.replace(/\/$/, '')
    const reachable = await probeLocalServer(url)

    console.log('Mode:   remote')
    console.log(`URL:    ${url}`)
    console.log('Auth:   env')
    console.log(reachable ? 'State:  reachable' : 'State:  unreachable')
    return
  }

  const config = readLocalConfig()
  const status = describeLocalServer()
  const service = describeLocalService()

  if (!config || !status.baseUrl) {
    printUnconfigured()
    return
  }

  const reachable = await probeLocalServer(status.baseUrl)

  console.log(`Config: ${status.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    ${status.baseUrl}`)
  console.log(`Log:    ${status.logFile}`)
  if (!service.supported) {
    console.log('Service: unsupported on this platform')
  } else if (!service.installed) {
    console.log('Service: not installed')
  } else {
    console.log(`Service: ${service.kind} (${service.filePath})`)
  }

  if (!status.running) {
    if (reachable) {
      console.log('State:  reachable (unmanaged)')
      return
    }

    console.log('State:  stopped')
    return
  }

  if (!reachable) {
    console.log(`State:  unresponsive (PID ${status.pid})`)
    return
  }

  console.log(`State:  running (PID ${status.pid})`)
}
