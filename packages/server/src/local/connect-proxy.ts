import { connect as connectTcp } from 'node:net'
import type { IncomingMessage, Server as HttpServer } from 'node:http'
import type { Duplex } from 'node:stream'
import { authorizeRequest, extractTokenFacts, getPublicKeyHex, getRevocationIds } from '../biscuit'
import { createLocalDb } from '../db/index'
import { isRevoked } from '../db/queries'
import {
  PROXY_TOKEN_HEADER,
  REQUESTED_ROOT_HEADER,
  extractProxyToken,
  isPrivateOrLocalAddress,
  resolveRequestedRoot,
} from '../proxy'
import { rootsForAction } from '../rights'
import type { LocalAgentPwConfig } from './config'
import { buildHeadersFromIncoming, maybeInjectLocalProxyToken } from './proxy-support'

type LocalDb = Awaited<ReturnType<typeof createLocalDb>>

export function parseConnectTarget(authority: string | undefined) {
  if (!authority) {
    return null
  }

  try {
    const url = new URL(`http://${authority}`)
    if (url.pathname !== '/' || url.search || url.hash) {
      return null
    }

    const port = url.port ? Number.parseInt(url.port, 10) : 443
    if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
      return null
    }

    return {
      hostname: url.hostname,
      port,
    }
  } catch {
    return null
  }
}

export function writeConnectResponse(
  socket: Duplex,
  status: number,
  statusText: string,
  body = '',
  headers: Array<[string, string]> = [],
) {
  const payload = Buffer.from(body, 'utf8')
  const lines = [
    `HTTP/1.1 ${status} ${statusText}`,
    'Connection: close',
    ...headers.map(([key, value]) => `${key}: ${value}`),
    `Content-Length: ${payload.length}`,
    '',
    body,
  ]
  socket.end(lines.join('\r\n'))
}

export async function authorizeConnectRequest(
  config: LocalAgentPwConfig,
  db: LocalDb,
  request: IncomingMessage,
  hostname: string,
): Promise<{
  status: number
  statusText: string
  body: string
  headers?: Array<[string, string]>
} | null> {
  const headers = buildHeadersFromIncoming(request)
  maybeInjectLocalProxyToken(headers, config, request.socket.remoteAddress)

  const token = extractProxyToken(headers.get(PROXY_TOKEN_HEADER) ?? undefined)
  if (!token) {
    return {
      status: 407,
      statusText: 'Proxy Authentication Required',
      body: 'Missing proxy credentials',
      headers: [
        ['Proxy-Authenticate', 'Basic realm="agent.pw"'],
        ['Proxy-Authenticate', 'Bearer realm="agent.pw"'],
      ] as Array<[string, string]>,
    }
  }

  const publicKeyHex = getPublicKeyHex(config.biscuitPrivateKey)

  try {
    const revocationIds = getRevocationIds(token, publicKeyHex)
    for (const id of revocationIds) {
      if (await isRevoked(db, id)) {
        return {
          status: 403,
          statusText: 'Forbidden',
          body: 'Token has been revoked',
        }
      }
    }
  } catch {
    return {
      status: 407,
      statusText: 'Proxy Authentication Required',
      body: 'Invalid proxy credentials',
      headers: [
        ['Proxy-Authenticate', 'Basic realm="agent.pw"'],
        ['Proxy-Authenticate', 'Bearer realm="agent.pw"'],
      ] as Array<[string, string]>,
    }
  }

  const tokenFacts = extractTokenFacts(token, publicKeyHex)
  const useRoots = rootsForAction(tokenFacts.rights, 'credential.use')
  if (useRoots.length === 0) {
    return {
      status: 403,
      statusText: 'Forbidden',
      body: 'Forbidden: requires "credential.use" right',
    }
  }

  const rootSelection = resolveRequestedRoot({
    tokenFacts,
    useRoots,
    requestedRootHeader: headers.get(REQUESTED_ROOT_HEADER),
  })
  if ('status' in rootSelection) {
    const status = rootSelection.status as 400 | 403 | 409
    const errorBody = rootSelection.body as { error?: string } | undefined
    return {
      status,
      statusText:
        status === 400
          ? 'Bad Request'
          : status === 403
            ? 'Forbidden'
            : 'Conflict',
      body: String(errorBody?.error ?? 'Proxy request failed'),
    }
  }

  const authorization = authorizeRequest(token, publicKeyHex, hostname, 'CONNECT', '/', {
    action: 'credential.use',
    host: hostname,
    requestedRoot: rootSelection.requestedRoot,
  })
  if (!authorization.authorized) {
    return {
      status: 403,
      statusText: 'Forbidden',
      body: authorization.error ?? 'Forbidden',
    }
  }

  return null
}

export async function handleConnectTunnel(
  config: LocalAgentPwConfig,
  db: LocalDb,
  request: IncomingMessage,
  clientSocket: Duplex,
  head: Buffer,
) {
  const target = parseConnectTarget(request.url)
  if (!target) {
    writeConnectResponse(clientSocket, 400, 'Bad Request', 'Invalid CONNECT target')
    return
  }

  if (isPrivateOrLocalAddress(target.hostname)) {
    writeConnectResponse(
      clientSocket,
      403,
      'Forbidden',
      `Refusing to proxy local or private target '${target.hostname}'`,
    )
    return
  }

  const authError = await authorizeConnectRequest(config, db, request, target.hostname)
  if (authError) {
    writeConnectResponse(
      clientSocket,
      authError.status,
      authError.statusText,
      authError.body,
      authError.headers ?? [],
    )
    return
  }

  const upstreamSocket = connectTcp(target.port, target.hostname)
  let established = false

  upstreamSocket.once('connect', () => {
    established = true
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')

    if (head.length > 0) {
      upstreamSocket.write(head)
    }

    upstreamSocket.pipe(clientSocket)
    clientSocket.pipe(upstreamSocket)
  })

  upstreamSocket.once('error', () => {
    if (!established) {
      writeConnectResponse(
        clientSocket,
        502,
        'Bad Gateway',
        `Could not connect to ${target.hostname}:${target.port}`,
      )
      return
    }

    clientSocket.destroy()
  })

  clientSocket.once('error', () => upstreamSocket.destroy())
  clientSocket.once('close', () => upstreamSocket.destroy())
}

export function attachConnectProxySupport(
  server: HttpServer,
  options: {
    config: LocalAgentPwConfig
    db: LocalDb
  },
  enabled = true,
) {
  if (!enabled) {
    return false
  }

  server.on('connect', async (request, clientSocket, head) => {
    await handleConnectTunnel(options.config, options.db, request, clientSocket, head)
  })

  return true
}
