import type { IncomingMessage } from 'node:http'
import { PROXY_TOKEN_HEADER } from '../proxy'
import type { LocalAgentPwConfig } from './config'
import { mintLocalRootToken } from './setup'

export function buildHeadersFromIncoming(incoming: IncomingMessage) {
  const headers = new Headers()

  for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
    const key = incoming.rawHeaders[index]
    const value = incoming.rawHeaders[index + 1]
    if (!key || value === undefined) {
      continue
    }
    headers.append(key, value)
  }

  return headers
}

export function isLoopbackAddress(address: string | undefined) {
  if (!address) {
    return false
  }

  const normalized = address.replace(/^::ffff:/, '').toLowerCase()
  return normalized === '127.0.0.1' || normalized === '::1'
}

export function maybeInjectLocalProxyToken(
  headers: Headers,
  config: LocalAgentPwConfig,
  remoteAddress: string | undefined,
) {
  if (headers.has(PROXY_TOKEN_HEADER) || !isLoopbackAddress(remoteAddress)) {
    return
  }

  headers.set(PROXY_TOKEN_HEADER, `Bearer ${mintLocalRootToken(config)}`)
}
