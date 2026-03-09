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

export async function login(host?: string) {
  const targetHost = (host ?? DEFAULT_MANAGED_HOST).replace(/\/$/, '')
  const config = await fetchCliAuthConfig(targetHost)
  if (config.provider !== 'workos_device') {
    console.error(`This host does not support cloud login.`)
    console.error('Use `agent.pw setup` for a local instance or configure AGENT_PW_HOST and AGENT_PW_TOKEN manually.')
    process.exit(1)
  }

  const device = await requestDeviceAuthorization(config.clientId)
  printDeviceInstructions(device)
  await openBrowser(device.verification_uri_complete ?? device.verification_uri)

  const auth = await pollForTokens({
    clientId: config.clientId,
    deviceCode: device.device_code,
    expiresIn: device.expires_in ?? 300,
    interval: device.interval ?? 5,
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
  console.log(`Logged in to ${targetHost}`)
}

async function fetchCliAuthConfig(targetHost: string): Promise<CliAuthConfig> {
  const res = await fetch(`${targetHost}/auth/cli/config`)
  if (!res.ok) {
    console.error(`This host does not advertise CLI auth (${res.status}).`)
    if (res.status === 404) {
      console.error('If this is self-hosted, use `agent.pw setup` locally or configure a token manually.')
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
}: {
  clientId: string
  deviceCode: string
  expiresIn: number
  interval: number
}): Promise<WorkOsAuthResponse> {
  const startedAt = Date.now()
  let delaySeconds = interval

  while (Date.now() - startedAt < expiresIn * 1000) {
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

function printDeviceInstructions(device: DeviceAuthorizationResponse) {
  console.log('Open the browser to authenticate with agent.pw.')
  console.log(`Code: ${device.user_code}`)
  console.log(`Verify at: ${device.verification_uri}`)
  if (device.verification_uri_complete) {
    console.log(`Or open directly: ${device.verification_uri_complete}`)
  }
}

async function openBrowser(url: string) {
  const { exec } = await import('node:child_process')
  const open = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open'
  exec(`${open} "${url}"`)
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
