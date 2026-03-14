import { readLocalConfig } from '../../../server/src/local/config'
import { describeLocalServer, probeLocalServer } from '../local/server-runtime'

function printUnconfigured() {
  console.log('No agent.pw instance is configured.')
  console.log('Run `npx agent.pw init` to create and start a local instance.')
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

  if (!config || !status.baseUrl) {
    printUnconfigured()
    return
  }

  const reachable = status.running ? await probeLocalServer(status.baseUrl) : false

  console.log(`Config: ${status.configFile}`)
  console.log(`Data:   ${config.dataDir}`)
  console.log(`URL:    ${status.baseUrl}`)
  console.log(`Log:    ${status.logFile}`)

  if (!status.running) {
    console.log('State:  stopped')
    return
  }

  if (!reachable) {
    console.log(`State:  unresponsive (PID ${status.pid})`)
    return
  }

  console.log(`State:  running (PID ${status.pid})`)
}
