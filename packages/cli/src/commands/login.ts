import { execSync } from 'node:child_process'
import { writeManagedSession } from '../config'
import { DEFAULT_MANAGED_HOST } from '../resolve'

type CliAuthConfig = {
  provider: 'workos_device'
  clientId: string
  exchangeUrl?: string
}

type DeviceAuthorizationResponse = {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete?: string
  expires_in?: number
  interval?: number
}

type WorkOsAuthResponse = {
  access_token: string
  refresh_token?: string
  user?: {
    id: string
    email?: string
  }
}

type LoginOptions = {
  skipNextSteps?: boolean
}

const canColor = process.stderr.isTTY ?? false
const bold = (s: string) => canColor ? `\x1b[1m${s}\x1b[0m` : s
const underline = (s: string) => canColor ? `\x1b[4m${s}\x1b[0m` : s
const dim = (s: string) => canColor ? `\x1b[2m${s}\x1b[0m` : s

export async function login(host?: string, token?: string, options: LoginOptions = {}) {
  const targetHost = (host ?? DEFAULT_MANAGED_HOST).replace(/\/$/, '')
  const { skipNextSteps = false } = options

  // Direct token login — skip device flow
  if (token) {
    writeManagedSession({ host: targetHost, token })
    console.error(`Logged in to ${targetHost}`)
    printNextSteps(skipNextSteps)
    return
  }
  const config = await fetchCliAuthConfig(targetHost)
  if (config.provider !== 'workos_device') {
    console.error(`This host does not support cloud login.`)
    console.error('Configure AGENT_PW_HOST and AGENT_PW_TOKEN environment variables for a self-hosted instance.')
    process.exit(1)
  }

  const device = await requestDeviceAuthorization(config.clientId)
  const verificationUrl = device.verification_uri_complete ?? device.verification_uri
  const browserOpened = tryOpenBrowser(verificationUrl)
  printDeviceInstructions(device, browserOpened)

  const interactiveStderr = process.stderr.isTTY ?? false
  if (interactiveStderr) {
    process.stderr.write(dim('Waiting for authentication...'))
  } else {
    console.error('Waiting for authentication...')
  }

  const auth = await pollForTokens({
    clientId: config.clientId,
    deviceCode: device.device_code,
    expiresIn: device.expires_in ?? 300,
    interval: device.interval ?? 5,
    onPoll: () => {
      if (interactiveStderr) {
        process.stderr.write('.')
      }
    },
  }).finally(() => {
    if (interactiveStderr) {
      process.stderr.write('\r\x1b[2K')
    }
  })

  const exchangeUrl = config.exchangeUrl ?? `${targetHost}/auth/cli/exchange`
  const exchange = await fetch(exchangeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accessToken: auth.access_token }),
  })

  if (!exchange.ok) {
    console.error(`Authentication exchange failed (${exchange.status}).`)
    console.error(await exchange.text())
    process.exit(1)
  }

  const data = await exchange.json() as { token: string }
  writeManagedSession({ host: targetHost, token: data.token })
  console.error(`Logged in to ${targetHost}`)
  printNextSteps(skipNextSteps)
}

async function fetchCliAuthConfig(targetHost: string): Promise<CliAuthConfig> {
  const res = await fetch(`${targetHost}/auth/cli/config`)
  if (!res.ok) {
    console.error(`This host does not advertise CLI auth (${res.status}).`)
    if (res.status === 404) {
      console.error('If this is self-hosted, configure AGENT_PW_HOST and AGENT_PW_TOKEN environment variables.')
    }
    process.exit(1)
  }
  return res.json() as Promise<CliAuthConfig>
}

async function requestDeviceAuthorization(clientId: string): Promise<DeviceAuthorizationResponse> {
  const res = await fetch('https://api.workos.com/user_management/authorize/device', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId }),
  })
  if (!res.ok) {
    console.error(`WorkOS device authorization failed (${res.status}).`)
    console.error(await res.text())
    process.exit(1)
  }
  return res.json() as Promise<DeviceAuthorizationResponse>
}

async function pollForTokens({
  clientId,
  deviceCode,
  expiresIn,
  interval,
  onPoll,
}: {
  clientId: string
  deviceCode: string
  expiresIn: number
  interval: number
  onPoll?: () => void
}): Promise<WorkOsAuthResponse> {
  const startedAt = Date.now()
  let delaySeconds = interval

  while (Date.now() - startedAt < expiresIn * 1000) {
    onPoll?.()
    const res = await fetch('https://api.workos.com/user_management/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: clientId,
      }),
    })

    const data = await res.json() as WorkOsAuthResponse & { error?: string }
    if (res.ok) {
      return data
    }

    switch (data.error) {
      case 'authorization_pending':
        break
      case 'slow_down':
        delaySeconds += 5
        break
      case 'access_denied':
        throw new Error('Authentication was denied in the browser.')
      case 'expired_token':
        throw new Error('Authentication timed out before it was completed.')
      default:
        throw new Error(`Authentication failed: ${data.error ?? res.statusText}`)
    }

    await sleep(delaySeconds * 1000)
  }

  throw new Error('Authentication timed out before it was completed.')
}

function printDeviceInstructions(device: DeviceAuthorizationResponse, browserOpened: boolean) {
  const verificationUrl = device.verification_uri_complete ?? device.verification_uri

  console.error('')
  console.error(
    browserOpened
      ? "A browser window should have opened. If it didn't, open the link below:"
      : 'Open the link below in your browser to log in:',
  )
  console.error(bold(underline(verificationUrl)))
  console.error(`Code: ${bold(device.user_code)}`)
  console.error('')
}

function tryOpenBrowser(url: string) {
  if (
    process.env.SSH_CLIENT
    || process.env.SSH_TTY
    || process.env.CODESPACES
    || process.env.REMOTE_CONTAINERS
    || !process.stdout.isTTY
  ) {
    return false
  }

  const quotedUrl = JSON.stringify(url)
  const openCommand = process.platform === 'darwin'
    ? `open ${quotedUrl}`
    : process.platform === 'win32'
      ? `start "" ${quotedUrl}`
      : `xdg-open ${quotedUrl}`

  try {
    execSync(openCommand, {
      stdio: 'ignore',
      timeout: 5000,
    })
    return true
  } catch {
    return false
  }
}

function printNextSteps(skipNextSteps = false) {
  if (skipNextSteps) {
    return
  }

  console.error('')
  console.error('Tip: run `npx agent.pw init` in your project to install the agent skill.')
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
