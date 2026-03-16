import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { getRequestListener } from '@hono/node-server'
import { createCoreApp } from '../core/app'
import { migrateLocal } from '../db/migrate-local'
import { createLocalDb } from '../db/index'
import { UPSTREAM_URL_HEADER } from '../proxy'
import { attachConnectProxySupport } from './connect-proxy'
import { buildLocalBaseUrl, type LocalAgentPwConfig } from './config'
import {
  buildHeadersFromIncoming,
  maybeInjectLocalProxyToken,
} from './proxy-support'

export const LOCAL_PROXY_FEATURES = Object.freeze({
  connectTunneling: true,
})

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

  const body = Readable.fromWeb(response.body)
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
    requestInit.body = Readable.toWeb(incoming)
    requestInit.duplex = 'half'
  }

  const response = await app.fetch(
    new Request(buildInternalProxyUrl(config, targetUrl), requestInit),
  )
  await writeFetchResponse(outgoing, response)
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
    attachConnectProxySupport(server, { config, db }, LOCAL_PROXY_FEATURES.connectTunneling)

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
  isForwardProxyRequest,
  buildInternalProxyUrl,
  writeFetchResponse,
  handleForwardProxyRequest,
}
