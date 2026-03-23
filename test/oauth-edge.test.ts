import { describe, expect, it } from 'vitest'
import { createInMemoryFlowStore, createOAuthService } from 'agent.pw/oauth'
import { AgentPwInputError } from '../packages/server/src/errors'
import type { CredentialProfileRecord, ResolvedCredential } from '../packages/server/src/types'

function makeProfile(overrides: Partial<CredentialProfileRecord> = {}): CredentialProfileRecord {
  return {
    path: '/provider',
    provider: 'provider',
    host: ['api.provider.com'],
    auth: null,
    oauthConfig: {
      clientId: 'client-id',
      authorizationUrl: 'https://accounts.example.com/authorize',
      tokenUrl: 'https://accounts.example.com/token',
    },
    displayName: 'Provider',
    description: null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
  }
}

function makeResolvedCredential(overrides: Partial<ResolvedCredential> = {}): ResolvedCredential {
  return {
    profilePath: '/provider',
    host: 'api.provider.com',
    path: '/org/connection/provider',
    auth: { kind: 'oauth' },
    secret: {
      headers: { Authorization: 'Bearer stale' },
      oauth: {
        accessToken: 'stale',
        refreshToken: 'refresh-token',
        expiresAt: '2020-01-01T00:00:00.000Z',
        scopes: 'repo',
      },
    },
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    profile: makeProfile(),
    ...overrides,
  }
}

describe('oauth edge cases', () => {
  it('validates flow input, missing config, missing state, unknown state, and expired state', async () => {
    const strayStore = createInMemoryFlowStore()
    await expect(strayStore.complete('missing')).resolves.toBeUndefined()
    await expect(strayStore.delete('missing')).resolves.toBeUndefined()

    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      getProfile: async () => null,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })

    await expect(service.startAuthorization({
      root: '/',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(service.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'not-a-url',
    })).rejects.toBeInstanceOf(AgentPwInputError)

    await expect(service.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toThrow("Credential Profile '/provider' has no OAuth configuration")

    await expect(service.completeAuthorization({
      callbackUri: 'https://app.example.com/callback?code=missing',
    })).rejects.toThrow('OAuth callback is missing state')

    await expect(service.completeAuthorization({
      callbackUri: 'https://app.example.com/callback?code=missing&state=unknown',
    })).rejects.toThrow("Unknown OAuth flow 'unknown'")

    const profile = makeProfile()
    const expiringService = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      getProfile: async () => profile,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })
    await expect(expiringService.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      credentialPath: '/',
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toBeInstanceOf(AgentPwInputError)
    const expired = await expiringService.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
      expiresAt: new Date('2025-12-31T23:59:59.000Z'),
    })
    await expect(expiringService.completeAuthorization({
      callbackUri: `https://app.example.com/callback?code=expired&state=${expired.flowId}`,
    })).rejects.toThrow(`OAuth flow '${expired.flowId}' has expired`)
  })

  it('supports issuer discovery, public clients, and additional authorization parameters', async () => {
    const flowStore = createInMemoryFlowStore()
    const putCalls: ResolvedCredential[] = []
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (
          url === 'https://issuer.example.com/.well-known/oauth-authorization-server'
          || url === 'https://issuer.example.com/.well-known/openid-configuration'
        ) {
          return Response.json({
            issuer: 'https://issuer.example.com',
            authorization_endpoint: 'https://issuer.example.com/authorize',
            token_endpoint: 'https://issuer.example.com/token',
          })
        }
        if (url === 'https://issuer.example.com/token') {
          return Response.json({
            access_token: 'issuer-access',
            expires_in: 300,
            token_type: 'Bearer',
          })
        }
        throw new Error(`unexpected url ${url}`)
      },
      getProfile: async () => makeProfile({
        auth: null,
        oauthConfig: {
          clientId: 'public-client',
          issuer: 'https://issuer.example.com',
          scopes: 'repo',
        },
      }),
      resolveBinding: async () => null,
      putBinding: async input => {
        const credential = makeResolvedCredential({
          path: input.credentialPath ?? '/org/connection/provider',
          secret: input.secret as ResolvedCredential['secret'],
          host: input.host ?? null,
          profile: makeProfile({
            auth: null,
            oauthConfig: {
              clientId: 'public-client',
              issuer: 'https://issuer.example.com',
              scopes: 'repo',
            },
          }),
        })
        putCalls.push(credential)
        return credential
      },
      deleteCredential: async () => false,
    })

    const session = await service.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
      additionalParameters: {
        prompt: 'consent',
      },
    })
    expect(session.authorizationUrl).toContain('scope=repo')
    expect(session.authorizationUrl).toContain('prompt=consent')

    const result = await service.completeAuthorization({
      callbackUri: `https://app.example.com/callback?code=public-code&state=${session.flowId}`,
    })
    expect(result.credential.secret.headers).toEqual({
      Authorization: 'Bearer issuer-access',
    })
    expect(putCalls).toHaveLength(1)
  })

  it('accepts explicit none client auth and auth payloads without authSchemes', async () => {
    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url === 'https://accounts.example.com/token') {
          return Response.json({
            access_token: 'explicit-none-access',
            expires_in: 300,
            token_type: 'Bearer',
          })
        }
        throw new Error(`unexpected url ${url}`)
      },
      getProfile: async () => makeProfile({
        auth: {
          authSchemes: undefined,
        },
        oauthConfig: {
          clientId: 'public-client',
          clientAuthentication: 'none',
          authorizationUrl: 'https://accounts.example.com/authorize',
          tokenUrl: 'https://accounts.example.com/token',
        },
      }),
      resolveBinding: async () => null,
      putBinding: async input => makeResolvedCredential({
        path: input.credentialPath ?? '/org/connection/provider',
        secret: input.secret as ResolvedCredential['secret'],
        auth: input.auth ?? { kind: 'oauth' },
      }),
      deleteCredential: async () => false,
    })

    const session = await service.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
    })
    const result = await service.completeAuthorization({
      callbackUri: `https://app.example.com/callback?code=public-code&state=${session.flowId}`,
    })
    expect(result.credential.secret.headers).toEqual({
      Authorization: 'Bearer explicit-none-access',
    })
  })

  it('defaults to client_secret_basic when a client secret is present', async () => {
    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url === 'https://accounts.example.com/token') {
          return Response.json({
            access_token: 'basic-default-access',
            expires_in: 300,
            token_type: 'Bearer',
          })
        }
        throw new Error(`unexpected url ${url}`)
      },
      getProfile: async () => makeProfile({
        auth: {},
        oauthConfig: {
          clientId: 'confidential-client',
          clientSecret: 'confidential-secret',
          authorizationUrl: 'https://accounts.example.com/authorize',
          tokenUrl: 'https://accounts.example.com/token',
        },
      }),
      resolveBinding: async () => null,
      putBinding: async input => makeResolvedCredential({
        path: input.credentialPath ?? '/org/connection/provider',
        secret: input.secret as ResolvedCredential['secret'],
        auth: input.auth ?? { kind: 'oauth' },
      }),
      deleteCredential: async () => false,
    })

    const session = await service.startAuthorization({
      root: '/org/connection',
      profilePath: '/provider',
      redirectUri: 'https://app.example.com/callback',
    })
    const result = await service.completeAuthorization({
      callbackUri: `https://app.example.com/callback?code=confidential-code&state=${session.flowId}`,
    })
    expect(result.credential.secret.headers).toEqual({
      Authorization: 'Bearer basic-default-access',
    })
  })

  it('short-circuits refreshes and preserves existing oauth fields when needed', async () => {
    const notExpired = makeResolvedCredential({
      secret: {
        headers: { Authorization: 'Bearer current' },
        oauth: {
          accessToken: 'current',
          refreshToken: 'refresh-token',
          expiresAt: '2099-01-01T00:00:00.000Z',
          scopes: 'repo',
        },
      },
    })

    const noRefreshToken = makeResolvedCredential({
      secret: {
        headers: { Authorization: 'Bearer stale' },
        oauth: {
          accessToken: 'stale',
          expiresAt: '2020-01-01T00:00:00.000Z',
        },
      },
    })

    const invalidExpiry = makeResolvedCredential({
      secret: {
        headers: { Authorization: 'Bearer stale' },
        oauth: {
          accessToken: 'stale',
          refreshToken: 'refresh-token',
          expiresAt: 'not-a-date',
        },
      },
    })

    let current = notExpired
    const basicService = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url === 'https://accounts.example.com/token') {
          return Response.json({
            access_token: 'fresh',
            expires_in: 600,
            token_type: 'Bearer',
          })
        }
        throw new Error(`unexpected url ${url}`)
      },
      getProfile: async path => path === '/missing-oauth'
        ? makeProfile({ oauthConfig: null })
        : makeProfile({
            oauthConfig: {
              clientId: 'basic-client',
              clientSecret: 'basic-secret',
              authorizationUrl: 'https://accounts.example.com/authorize',
              tokenUrl: 'https://accounts.example.com/token',
            },
          }),
      resolveBinding: async input => {
        if (input.profilePath === '/missing') return null
        if (input.profilePath === '/no-expiry') return notExpired
        if (input.profilePath === '/invalid-expiry') return invalidExpiry
        if (input.profilePath === '/no-refresh-token') return noRefreshToken
        if (input.profilePath === '/missing-oauth') return makeResolvedCredential({
          profilePath: '/missing-oauth',
          profile: makeProfile({ oauthConfig: null }),
        })
        return current
      },
      putBinding: async input => {
        current = makeResolvedCredential({
          path: input.credentialPath ?? '/org/connection/provider',
          profilePath: input.profilePath,
          host: input.host ?? null,
          auth: input.auth ?? { kind: 'oauth' },
          secret: input.secret as ResolvedCredential['secret'],
          profile: makeProfile({
            oauthConfig: {
              clientId: 'basic-client',
              clientSecret: 'basic-secret',
              authorizationUrl: 'https://accounts.example.com/authorize',
              tokenUrl: 'https://accounts.example.com/token',
            },
          }),
        })
        return current
      },
      deleteCredential: async () => true,
    })

    expect(await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/missing',
    })).toBeNull()

    expect(await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/no-expiry',
    })).toBe(notExpired)

    expect(await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/invalid-expiry',
    })).toBe(invalidExpiry)

    expect(await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/no-refresh-token',
    })).toBe(noRefreshToken)

    const missingOauth = await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/missing-oauth',
    })
    expect(missingOauth?.profile?.oauthConfig).toBeNull()

    const refreshed = await basicService.refreshCredential({
      root: '/org/connection',
      profilePath: '/provider',
      force: true,
    })
    expect(refreshed?.secret).toEqual(expect.objectContaining({
      headers: { Authorization: 'Bearer fresh' },
      oauth: expect.objectContaining({
        accessToken: 'fresh',
        refreshToken: 'refresh-token',
        scopes: 'repo',
      }),
    }))
  })

  it('handles disconnect fallbacks, custom web handlers, and CIMD validation', async () => {
    let deletedPath: string | null = null
    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      getProfile: async path => {
        if (path === '/missing-oauth') {
          return makeProfile({ oauthConfig: null })
        }
        return makeProfile()
      },
      resolveBinding: async input => {
        if (input.profilePath === '/missing') return null
        if (input.profilePath === '/missing-oauth') {
          return makeResolvedCredential({
            profilePath: '/missing-oauth',
            profile: makeProfile({ oauthConfig: null }),
          })
        }
        return makeResolvedCredential()
      },
      putBinding: async input => makeResolvedCredential({
        path: input.credentialPath ?? '/org/connection/provider',
        secret: input.secret as ResolvedCredential['secret'],
      }),
      deleteCredential: async path => {
        deletedPath = path
        return true
      },
    })

    expect(await service.disconnect({
      root: '/org/connection',
      profilePath: '/missing',
    })).toBe(false)

    expect(await service.disconnect({
      root: '/org/connection',
      profilePath: '/missing-oauth',
    })).toBe(true)
    expect(deletedPath).toBe('/org/connection/provider')

    const handlers = service.createWebHandlers({
      success(result) {
        return new Response(result.credentialPath, { status: 201 })
      },
      error(error) {
        return new Response(String(error), { status: 418 })
      },
    })

    const startResponse = await handlers.start(
      new Request('https://app.example.com/start'),
      {
        root: '/org/connection',
        profilePath: '/provider',
        redirectUri: 'https://app.example.com/callback',
      },
    )
    const location = startResponse.headers.get('location')
    expect(location).toContain('https://accounts.example.com/authorize')
    const flowId = new URL(String(location)).searchParams.get('state')
    expect(flowId).toBeTruthy()
    if (!flowId) {
      throw new Error('missing flow id')
    }

    service.completeAuthorization = async () => ({
      binding: { root: '/org/connection', profilePath: '/provider' },
      credentialPath: '/org/connection/provider',
      credential: makeResolvedCredential(),
    })
    expect((await handlers.callback(new Request(`https://app.example.com/callback?code=ok&state=${flowId}`))).status).toBe(201)

    service.completeAuthorization = async () => {
      throw 'custom failure'
    }
    const errorResponse = await service.createWebHandlers().callback(
      new Request('https://app.example.com/callback?code=missing&state=missing'),
    )
    expect(errorResponse.status).toBe(400)
    expect(await errorResponse.json()).toEqual({ error: 'OAuth flow failed' })

    const customErrorResponse = await handlers.callback(
      new Request('https://app.example.com/callback?code=missing&state=missing'),
    )
    expect(customErrorResponse.status).toBe(418)
    expect(await customErrorResponse.text()).toContain('custom failure')

    expect(() => service.createClientMetadataDocument({
      clientId: 'https://app.example.com/client.json',
      redirectUris: [],
    })).toThrow('CIMD requires at least one redirect URI')

    expect(service.createClientMetadataDocument({
      clientId: 'https://app.example.com/client.json',
      redirectUris: ['https://app.example.com/callback'],
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwksUri: 'https://app.example.com/jwks.json',
      tokenEndpointAuthSigningAlg: 'RS256',
    })).toEqual(expect.objectContaining({
      token_endpoint_auth_method: 'private_key_jwt',
      jwks_uri: 'https://app.example.com/jwks.json',
      token_endpoint_auth_signing_alg: 'RS256',
    }))
  })

  it('surfaces missing endpoint and client secret configuration errors', async () => {
    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      getProfile: async path => {
        if (path === '/missing-endpoint') {
          return makeProfile({
            oauthConfig: {
              clientId: 'client',
              tokenUrl: 'https://accounts.example.com/token',
            },
          })
        }
        return makeProfile({
          oauthConfig: {
            clientId: 'client',
            authorizationUrl: 'https://accounts.example.com/authorize',
            tokenUrl: 'https://accounts.example.com/token',
            clientAuthentication: 'client_secret_post',
          },
        })
      },
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url === 'https://accounts.example.com/token') {
          return Response.json({
            access_token: 'access',
            expires_in: 60,
            token_type: 'Bearer',
          })
        }
        throw new Error(`unexpected url ${url}`)
      },
      resolveBinding: async () => makeResolvedCredential({
        profile: makeProfile({
          oauthConfig: {
            clientId: 'client',
            authorizationUrl: 'https://accounts.example.com/authorize',
            tokenUrl: 'https://accounts.example.com/token',
            clientAuthentication: 'client_secret_post',
          },
        }),
      }),
      putBinding: async input => makeResolvedCredential({
        secret: input.secret as ResolvedCredential['secret'],
      }),
      deleteCredential: async () => true,
    })

    await expect(service.startAuthorization({
      root: '/org/connection',
      profilePath: '/missing-endpoint',
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toThrow('OAuth profiles require either issuer or authorizationUrl + tokenUrl')

    await expect(service.refreshCredential({
      root: '/org/connection',
      profilePath: '/provider',
      force: true,
    })).rejects.toThrow('OAuth client_secret_post requires clientSecret')
  })

  it('covers discovery failure, callback profile changes, and global fetch paths', async () => {
    const originalFetch = globalThis.fetch
    const requests: string[] = []
    globalThis.fetch = (async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      requests.push(url)

      if (url === 'https://issuer-no-auth.example.com/.well-known/openid-configuration') {
        return Response.json({
          issuer: 'https://issuer-no-auth.example.com',
          token_endpoint: 'https://issuer-no-auth.example.com/token',
        })
      }

      if (url === 'https://accounts.example.com/token') {
        const body = init?.body instanceof URLSearchParams
          ? init.body
          : new URLSearchParams(typeof init?.body === 'string' ? init.body : undefined)

        if (body.get('grant_type') === 'authorization_code') {
          return Response.json({
            access_token: 'auth-code-access',
            token_type: 'Bearer',
          })
        }

        return Response.json({
          access_token: 'refresh-access',
          token_type: 'Bearer',
        })
      }

      if (url === 'https://accounts.example.com/revoke') {
        return new Response(null, { status: 200 })
      }

      throw new Error(`unexpected fetch ${url}`)
    }) as typeof fetch

    try {
      const discoveryService = createOAuthService({
        flowStore: createInMemoryFlowStore(),
        clock: () => new Date('2026-01-01T00:00:00.000Z'),
        getProfile: async () => makeProfile({
          oauthConfig: {
            clientId: 'client',
            issuer: 'https://issuer-no-auth.example.com',
          },
        }),
        resolveBinding: async () => null,
        putBinding: async () => {
          throw new Error('not reached')
        },
        deleteCredential: async () => false,
      })

      await expect(discoveryService.startAuthorization({
        root: '/org/connection',
        profilePath: '/provider',
        redirectUri: 'https://app.example.com/callback',
      })).rejects.toThrow("Credential Profile '/provider' is missing an authorization endpoint")

      let mutableProfile: CredentialProfileRecord | null = makeProfile({
        auth: null,
        oauthConfig: {
          clientId: 'basic-client',
          clientSecret: 'basic-secret',
          clientAuthentication: 'client_secret_basic',
          authorizationUrl: 'https://accounts.example.com/authorize',
          tokenUrl: 'https://accounts.example.com/token',
          revocationUrl: 'https://accounts.example.com/revoke',
        },
      })

      const globalService = createOAuthService({
        flowStore: createInMemoryFlowStore(),
        clock: () => new Date('2026-01-01T00:00:00.000Z'),
        getProfile: async () => mutableProfile,
        resolveBinding: async () => makeResolvedCredential({
          profile: null,
        }),
        putBinding: async input => makeResolvedCredential({
          profile: mutableProfile,
          secret: input.secret as ResolvedCredential['secret'],
        }),
        deleteCredential: async () => true,
      })

      const successfulSession = await globalService.startAuthorization({
        root: '/org/connection',
        profilePath: '/provider',
        redirectUri: 'https://app.example.com/callback',
      })
      const successfulCompletion = await globalService.completeAuthorization({
        callbackUri: `https://app.example.com/callback?code=ok&state=${successfulSession.flowId}`,
      })
      expect(successfulCompletion.credential.secret.headers).toEqual({
        Authorization: 'Bearer auth-code-access',
      })

      const session = await globalService.startAuthorization({
        root: '/org/connection',
        profilePath: '/provider',
        redirectUri: 'https://app.example.com/callback',
      })
      mutableProfile = makeProfile({ oauthConfig: null })
      const completionAfterProfileChange = await globalService.completeAuthorization({
        callbackUri: `https://app.example.com/callback?code=abc&state=${session.flowId}`,
      })
      expect(completionAfterProfileChange.credential.secret.headers).toEqual({
        Authorization: 'Bearer auth-code-access',
      })

      mutableProfile = makeProfile({
        auth: null,
        oauthConfig: {
          clientId: 'basic-client',
          clientSecret: 'basic-secret',
          clientAuthentication: 'client_secret_basic',
          authorizationUrl: 'https://accounts.example.com/authorize',
          tokenUrl: 'https://accounts.example.com/token',
          revocationUrl: 'https://accounts.example.com/revoke',
        },
      })

      const refreshed = await globalService.refreshCredential({
        root: '/org/connection',
        profilePath: '/provider',
        force: true,
      })
      expect(refreshed?.secret.oauth?.accessToken).toBe('refresh-access')

      expect(await globalService.disconnect({
        root: '/org/connection',
        profilePath: '/provider',
        revoke: 'both',
      })).toBe(true)

      const missingSecretService = createOAuthService({
        flowStore: createInMemoryFlowStore(),
        clock: () => new Date('2026-01-01T00:00:00.000Z'),
        getProfile: async () => makeProfile({
          oauthConfig: {
            clientId: 'basic-client',
            clientAuthentication: 'client_secret_basic',
            authorizationUrl: 'https://accounts.example.com/authorize',
            tokenUrl: 'https://accounts.example.com/token',
          },
        }),
        resolveBinding: async () => makeResolvedCredential({
          profile: makeProfile({
            oauthConfig: {
              clientId: 'basic-client',
              clientAuthentication: 'client_secret_basic',
              authorizationUrl: 'https://accounts.example.com/authorize',
              tokenUrl: 'https://accounts.example.com/token',
            },
          }),
        }),
        putBinding: async input => makeResolvedCredential({
          secret: input.secret as ResolvedCredential['secret'],
        }),
        deleteCredential: async () => true,
      })

      await expect(missingSecretService.refreshCredential({
        root: '/org/connection',
        profilePath: '/provider',
        force: true,
      })).rejects.toThrow('OAuth client_secret_basic requires clientSecret')

      expect(requests).toEqual(expect.arrayContaining([
        'https://issuer-no-auth.example.com/.well-known/openid-configuration',
        'https://accounts.example.com/token',
        'https://accounts.example.com/revoke',
      ]))
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  it('covers resource discovery edge cases and resource credentials without stored client ids', async () => {
    const flowStore = createInMemoryFlowStore()
    const service = createOAuthService({
      flowStore,
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

        if (url.includes('/.well-known/oauth-protected-resource')) {
          return Response.json({
            resource: 'https://mcp.example.com',
            authorization_servers: ['https://issuer-no-auth.example.com'],
            resource_name: 'Example MCP',
          })
        }

        if (
          url === 'https://issuer-no-auth.example.com/.well-known/oauth-authorization-server'
          || url === 'https://issuer-no-auth.example.com/.well-known/openid-configuration'
        ) {
          return Response.json({
            issuer: 'https://issuer-no-auth.example.com',
            token_endpoint: 'https://issuer-no-auth.example.com/token',
          })
        }

        throw new Error(`unexpected fetch ${url}`)
      },
      getProfile: async () => null,
      resolveBinding: async () => makeResolvedCredential({
        profile: null,
        secret: {
          headers: { Authorization: 'Bearer resource-token' },
          oauth: {
            accessToken: 'resource-token',
            refreshToken: 'resource-refresh',
            expiresAt: '2020-01-01T00:00:00.000Z',
          },
        },
      }),
      putBinding: async input => makeResolvedCredential({
        path: input.credentialPath ?? '/org/connection/credential',
        profile: null,
        secret: input.secret as ResolvedCredential['secret'],
      }),
      deleteCredential: async () => true,
    })

    expect(await service.discoverResource({
      resource: 'https://mcp.example.com',
    })).toEqual({
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com/',
      },
      authorizationServers: ['https://issuer-no-auth.example.com'],
      resourceName: 'Example MCP',
      scopes: undefined,
    })

    await expect(service.startAuthorization({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com',
      },
      client: {
        clientId: 'https://app.example.com/.well-known/oauth-client',
      },
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toThrow("Resource 'https://mcp.example.com/' is missing an authorization endpoint")

    const unresolvedRefresh = await service.refreshCredential({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com',
      },
      force: true,
    })
    expect(unresolvedRefresh?.secret.headers).toEqual({
      Authorization: 'Bearer resource-token',
    })

    expect(await service.disconnect({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com',
      },
      revoke: 'both',
    })).toBe(true)
  })

  it('validates resource client registration requirements', async () => {
    const makeService = (withRegistrationEndpoint: boolean) => createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

        if (url.includes('/.well-known/oauth-protected-resource')) {
          return Response.json({
            resource: 'https://mcp.example.com',
            authorization_servers: ['https://issuer.example.com'],
          })
        }

        if (
          url === 'https://issuer.example.com/.well-known/oauth-authorization-server'
          || url === 'https://issuer.example.com/.well-known/openid-configuration'
        ) {
          return Response.json({
            issuer: 'https://issuer.example.com',
            authorization_endpoint: 'https://issuer.example.com/authorize',
            token_endpoint: 'https://issuer.example.com/token',
            registration_endpoint: withRegistrationEndpoint
              ? 'https://issuer.example.com/register'
              : undefined,
          })
        }

        throw new Error(`unexpected fetch ${url}`)
      },
      getProfile: async () => null,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })

    const binding = {
      root: '/org/connection',
      target: {
        kind: 'resource' as const,
        resource: 'https://mcp.example.com',
      },
      redirectUri: 'https://app.example.com/callback',
    }

    await expect(makeService(true).startAuthorization({
      ...binding,
      client: {
        useDynamicRegistration: true,
      },
    })).rejects.toThrow('Dynamic client registration requires client metadata')

    await expect(makeService(false).startAuthorization({
      ...binding,
      client: {
        useDynamicRegistration: true,
        metadata: {
          redirectUris: ['https://app.example.com/callback'],
        },
      },
    })).rejects.toThrow("Authorization server 'https://issuer.example.com' does not support dynamic client registration")

    await expect(makeService(true).startAuthorization({
      ...binding,
      client: {
        clientSecret: 'secret-only',
      },
    })).rejects.toThrow("Resource 'https://mcp.example.com/' requires a clientId or dynamic client registration")

    await expect(makeService(true).startAuthorization({
      ...binding,
    })).rejects.toThrow("Resource 'https://mcp.example.com/' requires oauth client configuration")

    const multiIssuerService = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

        if (url.includes('/.well-known/oauth-protected-resource')) {
          return Response.json({
            resource: 'https://mcp.example.com',
            authorization_servers: [
              'https://issuer-a.example.com',
              'https://issuer-b.example.com',
            ],
          })
        }

        throw new Error(`unexpected fetch ${url}`)
      },
      getProfile: async () => null,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })

    await expect(multiIssuerService.startAuthorization({
      ...binding,
      client: {
        clientId: 'https://app.example.com/.well-known/oauth-client',
      },
    })).rejects.toThrow("Resource 'https://mcp.example.com/' advertises multiple authorization servers; choose one explicitly")

    const noIssuerService = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url.includes('/.well-known/oauth-protected-resource')) {
          return Response.json({
            resource: 'https://mcp.example.com',
          })
        }
        throw new Error(`unexpected fetch ${url}`)
      },
      getProfile: async () => null,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })

    await expect(noIssuerService.startAuthorization({
      ...binding,
      client: {
        clientId: 'https://app.example.com/.well-known/oauth-client',
      },
    })).rejects.toThrow("Resource 'https://mcp.example.com/' does not advertise an authorization server")

    const explicitIssuerService = createOAuthService({
      flowStore: createInMemoryFlowStore(),
      clock: () => new Date('2026-01-01T00:00:00.000Z'),
      customFetch: async input => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        if (url.includes('/.well-known/oauth-protected-resource')) {
          return Response.json({
            resource: 'https://mcp.example.com',
            authorization_servers: ['https://issuer-a.example.com'],
          })
        }
        throw new Error(`unexpected fetch ${url}`)
      },
      getProfile: async () => null,
      resolveBinding: async () => null,
      putBinding: async () => {
        throw new Error('not reached')
      },
      deleteCredential: async () => false,
    })

    await expect(explicitIssuerService.startAuthorization({
      root: '/org/connection',
      target: {
        kind: 'resource',
        resource: 'https://mcp.example.com',
        authorizationServer: 'https://issuer-b.example.com',
      },
      client: {
        clientId: 'https://app.example.com/.well-known/oauth-client',
      },
      redirectUri: 'https://app.example.com/callback',
    })).rejects.toThrow(
      "Authorization server 'https://issuer-b.example.com/' is not advertised for resource 'https://mcp.example.com/'",
    )
  })

  it('supports resource discovery and dynamic registration through global fetch', async () => {
    const originalFetch = globalThis.fetch
    const requests: string[] = []
    globalThis.fetch = (async input => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      requests.push(url)

      if (url.includes('https://mcp.example.com') && url.includes('/.well-known/oauth-protected-resource')) {
        return Response.json({
          resource: 'https://mcp.example.com',
          authorization_servers: ['https://issuer.example.com'],
        })
      }

      if (url.includes('https://noauth.example.com') && url.includes('/.well-known/oauth-protected-resource')) {
        return Response.json({
          resource: 'https://noauth.example.com',
        })
      }

      if (
        url === 'https://issuer.example.com/.well-known/oauth-authorization-server'
        || url === 'https://issuer.example.com/.well-known/openid-configuration'
      ) {
        return Response.json({
          issuer: 'https://issuer.example.com',
          authorization_endpoint: 'https://issuer.example.com/authorize',
          token_endpoint: 'https://issuer.example.com/token',
          registration_endpoint: 'https://issuer.example.com/register',
        })
      }

      if (url === 'https://issuer.example.com/register') {
        return Response.json({
          client_id: 'https://app.example.com/.well-known/oauth-client',
          token_endpoint_auth_method: 'none',
        }, { status: 201 })
      }

      throw new Error(`unexpected fetch ${url}`)
    }) as typeof fetch

    try {
      const service = createOAuthService({
        flowStore: createInMemoryFlowStore(),
        clock: () => new Date('2026-01-01T00:00:00.000Z'),
        getProfile: async () => null,
        resolveBinding: async () => null,
        putBinding: async () => {
          throw new Error('not reached')
        },
        deleteCredential: async () => false,
      })

      const discovered = await service.discoverResource({
        resource: 'https://noauth.example.com',
      })
      expect(discovered.authorizationServers).toEqual([])

      const session = await service.startAuthorization({
        root: '/org/connection',
        target: {
          kind: 'resource',
          resource: 'https://mcp.example.com',
        },
        client: {
          useDynamicRegistration: true,
          metadata: {
            redirectUris: ['https://app.example.com/callback'],
            jwks: {
              keys: [],
            },
          },
        },
        redirectUri: 'https://app.example.com/callback',
      })
      expect(session.authorizationUrl).toContain('https://issuer.example.com/authorize')
      expect(requests).toEqual(expect.arrayContaining([
        'https://issuer.example.com/register',
      ]))
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
