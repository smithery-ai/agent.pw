import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { connect as connectTcp } from 'node:net'
import { Duplex, Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { getRequestListener } from '@hono/node-server'
import { authorizeRequest, extractTokenFacts, getPublicKeyHex, getRevocationIds } from '../biscuit'
import { createCoreApp } from '../core/app'
import { createLocalDb } from '../db/index'
import { isRevoked } from '../db/queries'
import { migrateLocal } from '../db/migrate-local'
import {
  PROXY_TOKEN_HEADER,
  REQUESTED_ROOT_HEADER,
  UPSTREAM_URL_HEADER,
  extractProxyToken,
  isPrivateOrLocalAddress,
  resolveRequestedRoot,
} from '../proxy'
import { rootsForAction } from '../rights'
import { buildLocalBaseUrl, type LocalAgentPwConfig } from './config'
import { mintLocalRootToken } from './setup'

async function createLocalServerContext(config: LocalAgentPwConfig) {
  const db = await createLocalDb(config.dataDir)
  await migrateLocal(db)

  const app = createCoreApp({
    db,
    biscuitPrivateKey: config.biscuitPrivateKey,
    baseUrl: buildLocalBaseUrl(config.port),
  })

  return { app, db }
}

export async function createLocalServerApp(config: LocalAgentPwConfig) {
  return (await createLocalServerContext(config)).app
}

function buildHeadersFromIncoming(incoming: IncomingMessage) {
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

function isLoopbackAddress(address: string | undefined) {
  if (!address) {
    return false
  }

  const normalized = address.replace(/^::ffff:/, '').toLowerCase()
  return normalized === '127.0.0.1' || normalized === '::1'
}

function maybeInjectLocalProxyToken(
  headers: Headers,
  config: LocalAgentPwConfig,
  remoteAddress: string | undefined,
) {
  if (headers.has(PROXY_TOKEN_HEADER) || !isLoopbackAddress(remoteAddress)) {
    return
  }

  headers.set(PROXY_TOKEN_HEADER, `Bearer ${mintLocalRootToken(config)}`)
}

function isForwardProxyRequest(incoming: IncomingMessage) {
  const url = incoming.url ?? ''
  return url.startsWith('http://') || url.startsWith('https://')
}

function buildInternalProxyUrl(config: LocalAgentPwConfig, targetUrl: URL) {
  return `${buildLocalBaseUrl(config.port)}/proxy/${targetUrl.hostname}${targetUrl.pathname}${targetUrl.search}`
}

async function writeFetchResponse(outgoing: ServerResponse, response: Response) {
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'transfer-encoding') {
      return
    }
    outgoing.setHeader(key, value)
  })

  outgoing.statusCode = response.status
  outgoing.statusMessage = response.statusText

  if (!response.body || response.status === 204 || response.status === 304) {
    outgoing.end()
    return
  }

  const body = Readable.fromWeb(response.body as globalThis.ReadableStream)
  body.on('error', error => outgoing.destroy(error))
  body.pipe(outgoing)
  await finished(outgoing)
}

async function handleForwardProxyRequest(
  app: Awaited<ReturnType<typeof createLocalServerApp>>,
  config: LocalAgentPwConfig,
  incoming: IncomingMessage,
  outgoing: ServerResponse,
) {
  let targetUrl: URL
  try {
    targetUrl = new URL(incoming.url ?? '')
  } catch {
    outgoing.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
    outgoing.end('Invalid proxy target URL')
    return
  }

  const headers = buildHeadersFromIncoming(incoming)
  maybeInjectLocalProxyToken(headers, config, incoming.socket.remoteAddress)
  headers.set(UPSTREAM_URL_HEADER, targetUrl.toString())

  const requestInit: RequestInit & { duplex?: 'half' } = {
    method: incoming.method ?? 'GET',
    headers,
  }
  if (!['GET', 'HEAD'].includes(incoming.method ?? 'GET')) {
    requestInit.body = Readable.toWeb(incoming) as unknown as ReadableStream
    requestInit.duplex = 'half'
  }

  const response = await app.fetch(
    new Request(buildInternalProxyUrl(config, targetUrl), requestInit),
  )
  await writeFetchResponse(outgoing, response)
}

function parseConnectTarget(authority: string | undefined) {
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

function writeConnectResponse(
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

async function authorizeConnectRequest(
  config: LocalAgentPwConfig,
  db: Awaited<ReturnType<typeof createLocalDb>>,
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

async function handleConnectTunnel(
  config: LocalAgentPwConfig,
  db: Awaited<ReturnType<typeof createLocalDb>>,
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

export async function serveLocalServer(
  config: LocalAgentPwConfig,
  hostname = '0.0.0.0',
) {
  const { app, db } = await createLocalServerContext(config)
  const requestListener = getRequestListener(app.fetch, { hostname })

  return await new Promise<ReturnType<typeof createServer>>((resolve, reject) => {
    let settled = false

    const server = createServer(async (incoming, outgoing) => {
      if (isForwardProxyRequest(incoming)) {
        await handleForwardProxyRequest(app, config, incoming, outgoing)
        return
      }

      await requestListener(incoming, outgoing)
    })

    server.on('connect', async (request, clientSocket, head) => {
      await handleConnectTunnel(config, db, request, clientSocket, head)
    })

    const onError = (error: NodeJS.ErrnoException) => {
      if (settled) {
        return
      }

      settled = true

      if (error.code === 'EADDRINUSE') {
        reject(new Error(`Failed to start server. Is port ${config.port} in use?`))
        return
      }

      reject(error)
    }

    server.once('error', onError)
    server.listen(config.port, hostname, () => {
      if (settled) {
        return
      }

      settled = true
      server.off('error', onError)
      resolve(server)
    })
  })
}

export const localServeTestUtils = {
  buildHeadersFromIncoming,
  isLoopbackAddress,
  maybeInjectLocalProxyToken,
  isForwardProxyRequest,
  buildInternalProxyUrl,
  writeFetchResponse,
  handleForwardProxyRequest,
  parseConnectTarget,
  writeConnectResponse,
  authorizeConnectRequest,
  handleConnectTunnel,
}
