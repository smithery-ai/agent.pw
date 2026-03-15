import { revokeToken } from '@agent.pw/server/db/queries'
import { getRevocationIds, mintToken, restrictToken } from '@agent.pw/server/biscuit'
import { PassThrough, Writable } from 'node:stream'
import { createServer as createTcpServer, connect as connectTcp, type Server as TcpServer, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mkdtempSync, rmSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PROXY_TOKEN_HEADER } from '../packages/server/src/proxy'
import { localServeTestUtils } from '../packages/server/src/local/serve'
import {
  BISCUIT_PRIVATE_KEY,
  PUBLIC_KEY_HEX,
  createTestDb,
  mintTestToken,
} from './setup'

const tempDirs: string[] = []
const activeServers: Array<{ close: (callback: (error?: Error) => void) => void }> = []
const activeSockets: Socket[] = []

afterEach(async () => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()

  await Promise.all(activeSockets.splice(0).map(socket => {
    socket.destroy()
    return Promise.resolve()
  }))

  await Promise.all(activeServers.splice(0).map(server => new Promise<void>((resolve, reject) => {
    server.close(error => {
      if (error) {
        reject(error)
        return
      }
      resolve()
    })
  })))

  tempDirs.splice(0).forEach(dir => {
    rmSync(dir, { recursive: true, force: true })
  })
})

function createTempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'agentpw-local-serve-test-'))
  tempDirs.push(dir)
  return dir
}

async function getFreePort() {
  const server = createTcpServer()
  return await new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to allocate a local port'))
        return
      }

      server.close(error => {
        if (error) {
          reject(error)
          return
        }
        resolve(address.port)
      })
    })
  })
}

function createConfig() {
  return {
    biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
    port: 9315,
    dataDir: createTempDir(),
  }
}

function makeIncomingRequest({
  url = '/',
  method = 'GET',
  headers = {},
  rawHeaders,
  remoteAddress = '127.0.0.1',
}: {
  url?: string
  method?: string
  headers?: Record<string, string>
  rawHeaders?: string[]
  remoteAddress?: string | undefined
} = {}) {
  return {
    url,
    method,
    rawHeaders: rawHeaders ?? Object.entries(headers).flatMap(([key, value]) => [key, value]),
    socket: { remoteAddress },
  } as any
}

function createOutgoingResponse() {
  const headers = new Map<string, string>()
  const chunks: Buffer[] = []

  return Object.assign(new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk))
      callback()
    },
  }), {
    statusCode: 200,
    statusMessage: '',
    headers,
    chunks,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), value)
    },
    getHeader(name: string) {
      return headers.get(name.toLowerCase())
    },
    writeHead(statusCode: number, nextHeaders?: Record<string, string>) {
      this.statusCode = statusCode
      Object.entries(nextHeaders ?? {}).forEach(([name, value]) => {
        headers.set(name.toLowerCase(), value)
      })
      return this
    },
    end(chunk?: string | Buffer) {
      if (chunk !== undefined) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
      }
      Writable.prototype.end.call(this)
      return this
    },
    bodyText() {
      return Buffer.concat(chunks).toString('utf8')
    },
  }) as Writable & {
    statusCode: number
    statusMessage: string
    headers: Map<string, string>
    chunks: Buffer[]
    setHeader: (name: string, value: string) => void
    getHeader: (name: string) => string | undefined
    writeHead: (statusCode: number, headers?: Record<string, string>) => unknown
    bodyText: () => string
  }
}

async function readStreamBody(stream: PassThrough) {
  const chunks: Buffer[] = []
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf8')
}

async function createSocketPair() {
  const server = createTcpServer()
  activeServers.push(server as TcpServer)

  const accepted = new Promise<Socket>((resolve, reject) => {
    server.once('error', reject)
    server.once('connection', socket => {
      activeSockets.push(socket)
      resolve(socket)
    })
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })

  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('Failed to create socket pair')
  }

  const clientSocket = connectTcp(address.port, '127.0.0.1')
  activeSockets.push(clientSocket)

  return {
    clientSocket,
    serverSocket: await accepted,
  }
}

function waitForSocketText(socket: Socket, predicate: (text: string) => boolean) {
  return new Promise<string>((resolve, reject) => {
    let text = ''

    const onData = (chunk: Buffer) => {
      text += Buffer.from(chunk).toString('utf8')
      if (predicate(text)) {
        cleanup()
        resolve(text)
      }
    }

    const onError = (error: Error) => {
      cleanup()
      reject(error)
    }

    const onClose = () => {
      cleanup()
      resolve(text)
    }

    const cleanup = () => {
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('close', onClose)
    }

    socket.on('data', onData)
    socket.once('error', onError)
    socket.once('close', onClose)
  })
}

describe('local serve helpers', () => {
  it('extracts incoming headers, detects loopback clients, and identifies proxy-form requests', () => {
    const config = createConfig()
    const headers = localServeTestUtils.buildHeadersFromIncoming(
      makeIncomingRequest({ rawHeaders: ['X-Test', 'ok', 'X-Skipped'] }),
    )
    expect(headers.get('x-test')).toBe('ok')
    expect(headers.get('x-skipped')).toBeNull()

    expect(localServeTestUtils.isLoopbackAddress(undefined)).toBe(false)
    expect(localServeTestUtils.isLoopbackAddress('::ffff:127.0.0.1')).toBe(true)
    expect(localServeTestUtils.isLoopbackAddress('::1')).toBe(true)
    expect(localServeTestUtils.isLoopbackAddress('10.0.0.5')).toBe(false)

    const existingAuth = new Headers({ [PROXY_TOKEN_HEADER]: 'Bearer explicit-token' })
    localServeTestUtils.maybeInjectLocalProxyToken(existingAuth, config, '127.0.0.1')
    expect(existingAuth.get(PROXY_TOKEN_HEADER)).toBe('Bearer explicit-token')

    const remoteHeaders = new Headers()
    localServeTestUtils.maybeInjectLocalProxyToken(remoteHeaders, config, '10.0.0.5')
    expect(remoteHeaders.has(PROXY_TOKEN_HEADER)).toBe(false)

    const loopbackHeaders = new Headers()
    localServeTestUtils.maybeInjectLocalProxyToken(loopbackHeaders, config, '127.0.0.1')
    expect(loopbackHeaders.get(PROXY_TOKEN_HEADER)).toMatch(/^Bearer apw_/)

    expect(
      localServeTestUtils.isForwardProxyRequest(makeIncomingRequest({ url: 'http://api.example.com/user' })),
    ).toBe(true)
    expect(
      localServeTestUtils.isForwardProxyRequest(makeIncomingRequest({ url: 'https://api.example.com/user' })),
    ).toBe(true)
    expect(
      localServeTestUtils.isForwardProxyRequest(makeIncomingRequest({ url: '/health' })),
    ).toBe(false)

    expect(
      localServeTestUtils.buildInternalProxyUrl(
        config,
        new URL('http://api.example.com:8080/user?mode=1'),
      ),
    ).toBe('http://127.0.0.1:9315/proxy/api.example.com/user?mode=1')
  })

  it('writes fetch responses and forwards proxy-form request bodies', async () => {
    const config = createConfig()

    const proxiedOutgoing = createOutgoingResponse()
    const proxiedIncoming = Object.assign(new PassThrough(), makeIncomingRequest({
      url: 'http://api.example.com/submit?mode=1',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }))
    const app = {
      fetch: vi.fn(async (request: Request) => new Response(JSON.stringify({
        url: request.url,
        upstreamUrl: request.headers.get('agentpw-upstream-url'),
        proxyAuthorization: request.headers.get(PROXY_TOKEN_HEADER),
        body: await request.text(),
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Transfer-Encoding': 'chunked',
        },
      })),
    }

    const forwardPromise = localServeTestUtils.handleForwardProxyRequest(
      app as any,
      config,
      proxiedIncoming as any,
      proxiedOutgoing as any,
    )
    proxiedIncoming.end(JSON.stringify({ ok: true }))
    await forwardPromise

    expect(proxiedOutgoing.statusCode).toBe(200)
    expect(proxiedOutgoing.getHeader('content-type')).toBe('application/json')
    expect(proxiedOutgoing.getHeader('transfer-encoding')).toBeUndefined()
    expect(JSON.parse(proxiedOutgoing.bodyText())).toEqual({
      url: 'http://127.0.0.1:9315/proxy/api.example.com/submit?mode=1',
      upstreamUrl: 'http://api.example.com/submit?mode=1',
      proxyAuthorization: expect.stringMatching(/^Bearer apw_/),
      body: '{"ok":true}',
    })

    const invalidOutgoing = createOutgoingResponse()
    await localServeTestUtils.handleForwardProxyRequest(
      app as any,
      config,
      makeIncomingRequest({ url: 'http://%' }),
      invalidOutgoing as any,
    )
    expect(invalidOutgoing.statusCode).toBe(400)
    expect(invalidOutgoing.bodyText()).toBe('Invalid proxy target URL')

    const emptyOutgoing = createOutgoingResponse()
    await localServeTestUtils.writeFetchResponse(
      emptyOutgoing as any,
      new Response(null, { status: 204, statusText: 'No Content' }),
    )
    expect(emptyOutgoing.statusCode).toBe(204)
    expect(emptyOutgoing.bodyText()).toBe('')
  })

  it('parses CONNECT targets and formats HTTP error responses', async () => {
    expect(localServeTestUtils.parseConnectTarget(undefined)).toBeNull()
    expect(localServeTestUtils.parseConnectTarget('example.com')).toEqual({
      hostname: 'example.com',
      port: 443,
    })
    expect(localServeTestUtils.parseConnectTarget('example.com/path')).toBeNull()
    expect(localServeTestUtils.parseConnectTarget('example.com:65536')).toBeNull()
    expect(localServeTestUtils.parseConnectTarget('[')).toBeNull()

    const socket = new PassThrough()
    localServeTestUtils.writeConnectResponse(
      socket,
      407,
      'Proxy Authentication Required',
      'Missing proxy credentials',
      [['Proxy-Authenticate', 'Basic realm="agent.pw"']],
    )

    const response = await readStreamBody(socket)
    expect(response).toContain('HTTP/1.1 407 Proxy Authentication Required')
    expect(response).toContain('Proxy-Authenticate: Basic realm="agent.pw"')
    expect(response).toContain('Content-Length: 25')
    expect(response).toContain('Missing proxy credentials')
  })

  it('authorizes CONNECT requests across success and failure paths', async () => {
    const config = createConfig()
    const db = await createTestDb()

    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({ remoteAddress: '10.0.0.5' }),
        'api.example.com',
      ),
    ).resolves.toEqual(expect.objectContaining({
      status: 407,
      body: 'Missing proxy credentials',
    }))

    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          remoteAddress: '10.0.0.5',
          headers: { [PROXY_TOKEN_HEADER]: 'Bearer bad-token' },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual(expect.objectContaining({
      status: 407,
      body: 'Invalid proxy credentials',
    }))

    const revokedToken = mintTestToken('org_alpha')
    await revokeToken(db as any, getRevocationIds(revokedToken, PUBLIC_KEY_HEX)[0], 'test')
    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          headers: { [PROXY_TOKEN_HEADER]: `Bearer ${revokedToken}` },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual({
      status: 403,
      statusText: 'Forbidden',
      body: 'Token has been revoked',
    })

    const noUseToken = mintToken(BISCUIT_PRIVATE_KEY, 'org_alpha', [
      { action: 'credential.manage', root: '/org_alpha' },
    ], [
      'org_id("org_alpha")',
      'home_path("/org_alpha")',
    ])
    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          headers: { [PROXY_TOKEN_HEADER]: `Bearer ${noUseToken}` },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual({
      status: 403,
      statusText: 'Forbidden',
      body: 'Forbidden: requires "credential.use" right',
    })

    const relativeWithoutHomePath = mintToken(BISCUIT_PRIVATE_KEY, 'org_alpha', [
      { action: 'credential.use', root: '/org_alpha' },
    ], [
      'org_id("org_alpha")',
    ])
    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          headers: {
            [PROXY_TOKEN_HEADER]: `Bearer ${relativeWithoutHomePath}`,
            'agentpw-path': 'shared',
          },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual({
      status: 409,
      statusText: 'Conflict',
      body: 'Relative agentpw-path requires token home_path metadata',
    })

    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          headers: {
            [PROXY_TOKEN_HEADER]: `Bearer ${mintTestToken('org_alpha')}`,
            'agentpw-path': '../bad',
          },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual({
      status: 400,
      statusText: 'Bad Request',
      body: "Invalid requested path '../bad'",
    })

    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest({
          headers: {
            [PROXY_TOKEN_HEADER]: `Bearer ${mintTestToken('org_alpha')}`,
            'agentpw-path': '/org_beta',
          },
        }),
        'api.example.com',
      ),
    ).resolves.toEqual({
      status: 403,
      statusText: 'Forbidden',
      body: "Forbidden: token cannot use requested path '/org_beta'",
    })

    const getOnlyToken = restrictToken(
      mintTestToken('org_alpha'),
      PUBLIC_KEY_HEX,
      [{ methods: 'GET' }],
    )
    const denied = await localServeTestUtils.authorizeConnectRequest(
      config,
      db as any,
      makeIncomingRequest({
        headers: { [PROXY_TOKEN_HEADER]: `Bearer ${getOnlyToken}` },
      }),
      'api.example.com',
    )
    expect(denied).toEqual(expect.objectContaining({
      status: 403,
      statusText: 'Forbidden',
    }))
    expect(denied?.body.length).toBeGreaterThan(0)

    await expect(
      localServeTestUtils.authorizeConnectRequest(
        config,
        db as any,
        makeIncomingRequest(),
        'api.example.com',
      ),
    ).resolves.toBeNull()
  })

  it('handles CONNECT tunnel setup, rejection, and upstream failures', async () => {
    const config = createConfig()
    const db = await createTestDb()

    const invalidTargetSocket = new PassThrough()
    await localServeTestUtils.handleConnectTunnel(
      config,
      db as any,
      makeIncomingRequest({ url: 'not a target/path' }),
      invalidTargetSocket as any,
      Buffer.alloc(0),
    )
    expect(await readStreamBody(invalidTargetSocket)).toContain('400 Bad Request')

    const privateTargetSocket = new PassThrough()
    await localServeTestUtils.handleConnectTunnel(
      config,
      db as any,
      makeIncomingRequest({ url: '127.0.0.1:443' }),
      privateTargetSocket as any,
      Buffer.alloc(0),
    )
    expect(await readStreamBody(privateTargetSocket)).toContain('403 Forbidden')

    const invalidAuthSocket = new PassThrough()
    await localServeTestUtils.handleConnectTunnel(
      config,
      db as any,
      makeIncomingRequest({
        url: 'public.example:443',
        headers: { [PROXY_TOKEN_HEADER]: 'Bearer bad-token' },
      }),
      invalidAuthSocket as any,
      Buffer.alloc(0),
    )
    expect(await readStreamBody(invalidAuthSocket)).toContain('407 Proxy Authentication Required')

    const echoPort = await getFreePort()
    const echoServer = createTcpServer(socket => {
      socket.on('data', chunk => socket.write(chunk))
    })
    await new Promise<void>((resolve, reject) => {
      echoServer.once('error', reject)
      echoServer.listen(echoPort, '127.0.0.1', () => resolve())
    })
    activeServers.push(echoServer as TcpServer)

    const successfulPair = await createSocketPair()
    await localServeTestUtils.handleConnectTunnel(
      config,
      db as any,
      makeIncomingRequest({ url: `proxy-target.localhost:${echoPort}` }),
      successfulPair.serverSocket as any,
      Buffer.from('head-'),
    )

    const establishedText = await waitForSocketText(
      successfulPair.clientSocket,
      text => text.includes('HTTP/1.1 200 Connection Established\r\n\r\nhead-'),
    )
    successfulPair.clientSocket.write('ping')
    const echoedText = await waitForSocketText(
      successfulPair.clientSocket,
      text => text.includes('ping'),
    )
    const successfulText = establishedText + echoedText
    expect(successfulText).toContain('HTTP/1.1 200 Connection Established')
    expect(successfulText).toContain('head-')
    expect(successfulText).toContain('ping')

    const refusedPort = await getFreePort()
    const refusedPair = await createSocketPair()
    await localServeTestUtils.handleConnectTunnel(
      config,
      db as any,
      makeIncomingRequest({ url: `proxy-target.localhost:${refusedPort}` }),
      refusedPair.serverSocket as any,
      Buffer.alloc(0),
    )
    expect(
      await waitForSocketText(refusedPair.clientSocket, text => text.includes('502 Bad Gateway')),
    ).toContain(`Could not connect to proxy-target.localhost:${refusedPort}`)
  })
})
