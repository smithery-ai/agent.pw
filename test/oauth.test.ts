import { describe, expect, it } from 'vitest'
import { createAgentPw } from 'agent.pw'
import { createInMemoryFlowStore } from 'agent.pw/oauth'
import { deriveEncryptionKey } from '../packages/server/src/lib/credentials-crypto'
import { AgentPwInputError } from '../packages/server/src/errors'
import { BISCUIT_PRIVATE_KEY, createTestDb } from './setup'

function createOAuthFetch() {
  const calls: Array<{
    url: string
    body: URLSearchParams
  }> = []

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const body = init?.body instanceof URLSearchParams
      ? init.body
      : new URLSearchParams(typeof init?.body === 'string' ? init.body : undefined)

    calls.push({ url, body })

    if (url === 'https://accounts.example.com/token') {
      if (body.get('grant_type') === 'authorization_code') {
        return Response.json({
          access_token: 'access-1',
          refresh_token: 'refresh-1',
          expires_in: 3600,
          scope: 'read write',
          token_type: 'Bearer',
        })
      }

      if (body.get('grant_type') === 'refresh_token') {
        return Response.json({
          access_token: 'access-2',
          refresh_token: 'refresh-2',
          expires_in: 7200,
          scope: 'read write',
          token_type: 'Bearer',
        })
      }
    }

    if (url === 'https://accounts.example.com/revoke') {
      return new Response(null, { status: 200 })
    }

    throw new Error(`Unexpected oauth fetch: ${url}`)
  }

  return { fetchImpl, calls }
}

async function createOAuthAgent() {
  const db = await createTestDb()
  const flowStore = createInMemoryFlowStore()
  const encryptionKey = await deriveEncryptionKey(BISCUIT_PRIVATE_KEY)
  const { fetchImpl, calls } = createOAuthFetch()
  const agentPw = await createAgentPw({
    db,
    encryptionKey,
    flowStore,
    oauthFetch: fetchImpl,
  })

  await agentPw.profiles.put('/linear', {
    host: ['api.linear.app'],
    auth: {
      authSchemes: [
        {
          type: 'oauth2',
          authorizeUrl: 'https://accounts.example.com/authorize',
          tokenUrl: 'https://accounts.example.com/token',
        },
      ],
    },
    oauthConfig: {
      clientId: 'client-linear',
      clientSecret: 'secret-linear',
      clientAuthentication: 'client_secret_post',
      revocationUrl: 'https://accounts.example.com/revoke',
      scopes: ['read', 'write'],
    },
  })

  return { agentPw, calls }
}

describe('oauth runtime', () => {
  it('starts and completes OAuth authorization flows', async () => {
    const { agentPw, calls } = await createOAuthAgent()

    const session = await agentPw.oauth.startAuthorization({
      root: '/org_alpha/connections/linear_1',
      profilePath: '/linear',
      credentialPath: '/org_alpha/connections/linear_1/custom_linear',
      redirectUri: 'https://app.example.com/oauth/callback',
    })

    expect(session.flowId).toHaveLength(96)
    expect(session.authorizationUrl).toContain('https://accounts.example.com/authorize')
    expect(session.authorizationUrl).toContain('client_id=client-linear')
    expect(session.authorizationUrl).toContain(`state=${session.flowId}`)
    expect(await agentPw.oauth.getFlow(session.flowId)).toEqual(expect.objectContaining({
      id: session.flowId,
      root: '/org_alpha/connections/linear_1',
      profilePath: '/linear',
    }))

    const result = await agentPw.oauth.completeAuthorization({
      callbackUri: `https://app.example.com/oauth/callback?code=code-123&state=${session.flowId}`,
    })

    expect(result.credentialPath).toBe('/org_alpha/connections/linear_1/custom_linear')
    expect(result.credential.secret).toEqual(expect.objectContaining({
      headers: { Authorization: 'Bearer access-1' },
      oauth: expect.objectContaining({
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        scopes: 'read write',
        tokenType: 'bearer',
      }),
    }))
    expect(await agentPw.oauth.getFlow(session.flowId)).toBeNull()
    expect(calls.map(call => call.url)).toContain('https://accounts.example.com/token')
  })

  it('refreshes expired credentials before resolving headers', async () => {
    const { agentPw } = await createOAuthAgent()

    await agentPw.bindings.put({
      root: '/org_alpha/connections/linear_2',
      profilePath: '/linear',
      secret: {
        headers: { Authorization: 'Bearer stale' },
        oauth: {
          accessToken: 'stale',
          refreshToken: 'refresh-1',
          expiresAt: '2020-01-01T00:00:00.000Z',
          scopes: 'read write',
        },
      },
    })

    expect(await agentPw.bindings.resolveHeaders({
      root: '/org_alpha/connections/linear_2',
      profilePath: '/linear',
    })).toEqual({
      Authorization: 'Bearer access-2',
    })

    const resolved = await agentPw.oauth.refreshCredential({
      root: '/org_alpha/connections/linear_2',
      profilePath: '/linear',
      force: true,
    })
    expect(resolved?.secret.oauth).toEqual(expect.objectContaining({
      accessToken: 'access-2',
      refreshToken: 'refresh-2',
    }))
  })

  it('hosts callback helpers, serves CIMD, and disconnects credentials', async () => {
    const { agentPw, calls } = await createOAuthAgent()

    const metadata = agentPw.oauth.createClientMetadataDocument({
      clientId: 'https://app.example.com/.well-known/client.json',
      redirectUris: ['https://app.example.com/oauth/callback'],
      clientName: 'Connect Client',
      scope: ['mcp.tools.read', 'mcp.resources.read'],
      tokenEndpointAuthMethod: 'none',
    })
    expect(metadata).toEqual(expect.objectContaining({
      client_id: 'https://app.example.com/.well-known/client.json',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
    }))

    const metadataResponse = agentPw.oauth.createClientMetadataResponse({
      clientId: 'https://app.example.com/.well-known/client.json',
      redirectUris: ['https://app.example.com/oauth/callback'],
    })
    expect(metadataResponse.headers.get('content-type')).toContain('application/json')

    const handlers = agentPw.oauth.createWebHandlers({
      callbackPath: '/connect/callback',
    })

    const startResponse = await handlers.start(
      new Request('https://app.example.com/connect/start'),
      {
        root: '/org_alpha/connections/linear_3',
        profilePath: '/linear',
      },
    )
    expect(startResponse.status).toBe(302)
    const location = startResponse.headers.get('location')
    expect(location).toContain('redirect_uri=https%3A%2F%2Fapp.example.com%2Fconnect%2Fcallback')
    const state = new URL(String(location)).searchParams.get('state')
    expect(state).toBeTruthy()
    if (!state) {
      throw new Error('missing state')
    }

    const callbackResponse = await handlers.callback(
      new Request(`https://app.example.com/connect/callback?code=code-456&state=${state}`),
    )
    expect(callbackResponse.status).toBe(200)
    expect(await callbackResponse.text()).toContain('Authorization complete')

    expect(await agentPw.oauth.disconnect({
      root: '/org_alpha/connections/linear_3',
      profilePath: '/linear',
      revoke: 'both',
    })).toBe(true)

    expect(await agentPw.credentials.resolve({
      root: '/org_alpha/connections/linear_3',
      profilePath: '/linear',
      refresh: false,
    })).toBeNull()
    expect(calls.filter(call => call.url === 'https://accounts.example.com/revoke')).toHaveLength(2)
  })

  it('requires an explicit flow store for hosted OAuth and returns default callback errors', async () => {
    const db = await createTestDb()
    const agentPw = await createAgentPw({
      db,
      encryptionKey: await deriveEncryptionKey(BISCUIT_PRIVATE_KEY),
    })

    await agentPw.profiles.put('/github', {
      host: ['api.github.com'],
      auth: {
        authSchemes: [
          {
            type: 'oauth2',
            authorizeUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
          },
        ],
      },
      oauthConfig: {
        clientId: 'client-github',
      },
    })

    await expect(agentPw.oauth.startAuthorization({
      root: '/org_alpha/connections/github_1',
      profilePath: '/github',
      redirectUri: 'https://app.example.com/oauth/callback',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    const callbackResponse = await agentPw.oauth.createWebHandlers().callback(
      new Request('https://app.example.com/oauth/callback?code=missing&state=missing'),
    )
    expect(callbackResponse.status).toBe(400)
    expect(await callbackResponse.json()).toEqual({
      error: "OAuth flows require an explicit flowStore",
    })
  })
})
