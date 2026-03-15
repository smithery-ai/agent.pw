import { request as httpRequest } from 'node:http'
import { createServer as createTcpServer, connect as connectTcp, type Server as TcpServer, type Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { mkdtempSync, rmSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  buildCredentialHeaders,
  deriveEncryptionKey,
  encryptCredentials,
} from '@agent.pw/server/crypto'
import { upsertCredential } from '@agent.pw/server/db/queries'
import { createLocalDb } from '../packages/server/src/db/index'
import { migrateLocal } from '../packages/server/src/db/migrate-local'
import { serveLocalServer } from '../packages/server/src/local/serve'
import { BISCUIT_PRIVATE_KEY } from './setup'

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
  const dir = mkdtempSync(join(tmpdir(), 'agentpw-proxy-test-'))
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

async function storeBearerCredential(dataDir: string, host: string, token: string) {
  const db = await createLocalDb(dataDir)
  await migrateLocal(db)

  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const secret = await encryptCredentials(encryptionKey, {
    headers: buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, token),
  })

  await upsertCredential(db, {
    host,
    path: `/${host}`,
    auth: { kind: 'headers' },
    secret,
  })
}

async function sendProxyRequest(port: number, targetUrl: string) {
  return await new Promise<{
    status: number
    body: string
  }>((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port,
      method: 'GET',
      path: targetUrl,
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
        })
      })
    })

    req.on('error', reject)
    req.end()
  })
}

async function openConnectTunnel(port: number, authority: string) {
  const socket = connectTcp(port, '127.0.0.1')
  activeSockets.push(socket)

  return await new Promise<{ socket: Socket; response: string }>((resolve, reject) => {
    let buffered = Buffer.alloc(0)

    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, Buffer.from(chunk)])
      const separator = buffered.indexOf('\r\n\r\n')
      if (separator === -1) {
        return
      }

      socket.off('data', onData)
      resolve({
        socket,
        response: buffered.subarray(0, separator + 4).toString('utf8'),
      })
    }

    socket.once('error', reject)
    socket.on('data', onData)
    socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
  })
}

describe('local proxy server', () => {
  it('accepts standard proxy-form HTTP requests and injects local credentials', async () => {
    const dataDir = createTempDir()
    const port = await getFreePort()

    await storeBearerCredential(dataDir, 'api.github.com', 'ghp_local_proxy')

    vi.stubGlobal('fetch', vi.fn(async (_input, init) => {
      const headers = new Headers(init?.headers)
      return new Response(JSON.stringify({
        authorization: headers.get('Authorization'),
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }))

    const server = await serveLocalServer({
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      port,
      dataDir,
    }, '127.0.0.1')
    activeServers.push(server)

    const response = await sendProxyRequest(port, 'http://api.github.com/user')
    expect(response.status).toBe(200)
    expect(JSON.parse(response.body)).toEqual({
      authorization: 'Bearer ghp_local_proxy',
    })
  })

  it('opens CONNECT tunnels for loopback clients after proxy auth is resolved locally', async () => {
    const dataDir = createTempDir()
    const proxyPort = await getFreePort()
    const targetPort = await getFreePort()
    const targetHost = 'proxy-target.localhost'

    const echoServer = createTcpServer(socket => {
      socket.on('data', chunk => socket.write(chunk))
    })
    await new Promise<void>((resolve, reject) => {
      echoServer.once('error', reject)
      echoServer.listen(targetPort, '::1', () => resolve())
    })
    activeServers.push(echoServer as TcpServer)

    const proxyServer = await serveLocalServer({
      biscuitPrivateKey: BISCUIT_PRIVATE_KEY,
      port: proxyPort,
      dataDir,
    }, '127.0.0.1')
    activeServers.push(proxyServer)

    const { socket, response } = await openConnectTunnel(
      proxyPort,
      `${targetHost}:${targetPort}`,
    )
    expect(response).toContain('200 Connection Established')

    const echoed = await new Promise<string>((resolve, reject) => {
      socket.once('error', reject)
      socket.once('data', chunk => resolve(Buffer.from(chunk).toString('utf8')))
      socket.write('ping')
    })

    expect(echoed).toBe('ping')
  })
})
