import * as oauth from 'oauth4webapi'
import { buildCredentialHeaders, type StoredCredentials } from './lib/credentials-crypto.js'
import { AgentPwInputError } from './errors.js'
import { getOAuthScheme, parseAuthSchemes } from './auth-schemes.js'
import { isRecord, randomId, validateFlowId } from './lib/utils.js'
import { canonicalizePath, validatePath } from './paths.js'
import type {
  BindingPutInput,
  BindingRef,
  CimdDocument,
  CimdDocumentInput,
  CompletedFlowResult,
  CredentialProfileRecord,
  OAuthAuthorizationSession,
  OAuthClientAuthenticationMethod,
  OAuthCompleteAuthorizationInput,
  OAuthCompletionResult,
  OAuthDisconnectInput,
  OAuthProfileConfig,
  OAuthRefreshInput,
  OAuthStartAuthorizationInput,
  OAuthWebHandlers,
  PendingFlow,
  ResolvedCredential,
  FlowStore,
} from './types.js'

function assertResolvablePath(path: string, label: string) {
  const normalized = canonicalizePath(path)
  if (!validatePath(normalized) || normalized === '/') {
    throw new AgentPwInputError(`Invalid ${label} '${path}'`)
  }
  return normalized
}

function assertUrl(value: string, label: string) {
  try {
    return new URL(value)
  } catch {
    throw new AgentPwInputError(`Invalid ${label} '${value}'`)
  }
}

function stringValue(value: unknown) {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function stringArrayValue(value: unknown) {
  if (Array.isArray(value)) {
    return value.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
  }
  return []
}

function toScopeString(value: string | string[] | undefined) {
  if (Array.isArray(value)) {
    return value.join(' ')
  }
  return value
}

function defaultExpiry(clock: () => Date) {
  return new Date(clock().getTime() + 10 * 60 * 1000)
}

function normalizeClientAuthentication(value: string | undefined, hasSecret: boolean): OAuthClientAuthenticationMethod {
  if (value === 'client_secret_basic') {
    return value
  }
  if (value === 'client_secret_post') {
    return value
  }
  if (value === 'none') {
    return value
  }
  if (hasSecret) {
    return 'client_secret_basic'
  }
  return 'none'
}

function profileAuthSchemes(profile: CredentialProfileRecord) {
  if (!isRecord(profile.auth)) {
    return []
  }
  if (!('authSchemes' in profile.auth)) {
    return []
  }

  return parseAuthSchemes(JSON.stringify(profile.auth.authSchemes ?? []))
}

function parseOAuthProfileConfig(profile: CredentialProfileRecord | null): OAuthProfileConfig | null {
  if (!profile) {
    return null
  }

  const oauthConfig = profile.oauthConfig ?? {}
  const oauthScheme = getOAuthScheme(profileAuthSchemes(profile))

  const clientId = stringValue(oauthConfig.clientId)
  if (!clientId) {
    return null
  }

  const clientSecret = stringValue(oauthConfig.clientSecret)
  return {
    issuer: stringValue(oauthConfig.issuer),
    authorizationUrl: stringValue(oauthConfig.authorizationUrl) ?? stringValue(oauthConfig.authorizeUrl) ?? oauthScheme?.authorizeUrl,
    tokenUrl: stringValue(oauthConfig.tokenUrl) ?? oauthScheme?.tokenUrl,
    revocationUrl: stringValue(oauthConfig.revocationUrl),
    clientId,
    clientSecret,
    clientAuthentication: normalizeClientAuthentication(stringValue(oauthConfig.clientAuthentication), Boolean(clientSecret)),
    scopes: stringValue(oauthConfig.scopes) ?? stringArrayValue(oauthConfig.scopes),
  }
}

function profileOAuthHeaders(profile: CredentialProfileRecord, accessToken: string) {
  const authSchemes = profileAuthSchemes(profile)
  const oauthScheme = getOAuthScheme(authSchemes)
  if (oauthScheme) {
    return buildCredentialHeaders(oauthScheme, accessToken)
  }
  return buildCredentialHeaders({ type: 'http', scheme: 'bearer' }, accessToken)
}

function oauthSecretFromTokenResponse(
  profile: CredentialProfileRecord,
  response: oauth.TokenEndpointResponse,
  existing?: StoredCredentials,
): StoredCredentials {
  const accessToken = response.access_token
  const refreshToken = response.refresh_token ?? existing?.oauth?.refreshToken ?? null
  const expiresAt = typeof response.expires_in === 'number'
    ? new Date(Date.now() + response.expires_in * 1000).toISOString()
    : existing?.oauth?.expiresAt

  return {
    headers: profileOAuthHeaders(profile, accessToken),
    oauth: {
      accessToken,
      refreshToken,
      expiresAt,
      scopes: typeof response.scope === 'string' ? response.scope : existing?.oauth?.scopes,
      tokenType: response.token_type,
    },
  }
}

function shouldRefresh(secret: StoredCredentials | undefined, clock: () => Date, force = false) {
  if (force) {
    return true
  }
  const expiresAt = secret?.oauth?.expiresAt
  if (!expiresAt) {
    return false
  }
  const parsed = new Date(expiresAt)
  if (Number.isNaN(parsed.getTime())) {
    return false
  }
  return parsed.getTime() <= clock().getTime() + 60_000
}

function buildClientAuthentication(config: OAuthProfileConfig) {
  switch (config.clientAuthentication) {
    case 'client_secret_post':
      if (!config.clientSecret) {
        throw new AgentPwInputError('OAuth client_secret_post requires clientSecret')
      }
      return oauth.ClientSecretPost(config.clientSecret)
    case 'client_secret_basic':
      if (!config.clientSecret) {
        throw new AgentPwInputError('OAuth client_secret_basic requires clientSecret')
      }
      return oauth.ClientSecretBasic(config.clientSecret)
    case 'none':
      return oauth.None()
  }
}

function buildClient(config: OAuthProfileConfig): oauth.Client {
  return {
    client_id: config.clientId,
  }
}

async function resolveAuthorizationServer(
  config: OAuthProfileConfig,
  customFetch: typeof fetch | undefined,
) {
  if (config.issuer) {
    const issuer = assertUrl(config.issuer, 'oauth issuer')
    const response = await oauth.discoveryRequest(issuer, customFetch
      ? { [oauth.customFetch]: customFetch }
      : undefined)
    return oauth.processDiscoveryResponse(issuer, response)
  }

  if (!(config.authorizationUrl && config.tokenUrl)) {
    throw new AgentPwInputError('OAuth profiles require either issuer or authorizationUrl + tokenUrl')
  }

  return {
    issuer: new URL(config.authorizationUrl).origin,
    authorization_endpoint: config.authorizationUrl,
    token_endpoint: config.tokenUrl,
    revocation_endpoint: config.revocationUrl,
  } satisfies oauth.AuthorizationServer
}

function resolveRedirectUri(request: Request, callbackPath: string) {
  const url = new URL(request.url)
  const callbackUrl = new URL(callbackPath, url)
  return callbackUrl.toString()
}

function defaultSuccessResponse() {
  return new Response(
    '<!doctype html><html><body><p>Authorization complete. You can close this window.</p></body></html>',
    {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
      },
    },
  )
}

function defaultErrorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : 'OAuth flow failed'
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 400,
      headers: {
        'content-type': 'application/json; charset=utf-8',
      },
    },
  )
}

export function createInMemoryFlowStore(): FlowStore {
  const store = new Map<string, PendingFlow>()

  return {
    async create(flow) {
      store.set(flow.id, flow)
    },
    async get(id) {
      return store.get(id) ?? null
    },
    async complete(id, _result?: CompletedFlowResult) {
      if (!store.has(id)) {
        return
      }
      store.delete(id)
    },
    async delete(id) {
      store.delete(id)
    },
  }
}

export function createOAuthService(options: {
  flowStore?: FlowStore
  clock: () => Date
  customFetch?: typeof fetch
  getProfile(path: string): Promise<CredentialProfileRecord | null>
  resolveBinding(input: BindingRef & {
    credentialPath?: string
    refresh?: boolean
  }): Promise<ResolvedCredential | null>
  putBinding(input: BindingPutInput): Promise<ResolvedCredential>
  deleteCredential(path: string): Promise<boolean>
}) {
  async function requireFlowStore() {
    if (!options.flowStore) {
      throw new AgentPwInputError('OAuth flows require an explicit flowStore')
    }
    return options.flowStore
  }

  async function refreshResolvedCredential(
    resolved: ResolvedCredential | null,
    input: OAuthRefreshInput,
  ) {
    if (!resolved) {
      return null
    }
    if (!shouldRefresh(resolved.secret, options.clock, input.force)) {
      return resolved
    }

    const refreshToken = resolved.secret.oauth?.refreshToken
    if (!refreshToken) {
      return resolved
    }

    const profile = resolved.profile ?? await options.getProfile(input.profilePath)
    const oauthConfig = parseOAuthProfileConfig(profile)
    if (!(profile && oauthConfig)) {
      return resolved
    }

    const authorizationServer = await resolveAuthorizationServer(oauthConfig, options.customFetch)
    const client = buildClient(oauthConfig)
    const clientAuthentication = buildClientAuthentication(oauthConfig)
    const tokenResponse = await oauth.refreshTokenGrantRequest(
      authorizationServer,
      client,
      clientAuthentication,
      refreshToken,
      options.customFetch
        ? { [oauth.customFetch]: options.customFetch }
        : undefined,
    )
    const processed = await oauth.processRefreshTokenResponse(authorizationServer, client, tokenResponse)
    return options.putBinding({
      root: input.root,
      profilePath: input.profilePath,
      credentialPath: resolved.path,
      host: resolved.host,
      auth: resolved.auth,
      secret: oauthSecretFromTokenResponse(profile, processed, resolved.secret),
    })
  }

  return {
    async getFlow(id: string) {
      const flowStore = await requireFlowStore()
      return flowStore.get(id)
    },

    async startAuthorization(input: OAuthStartAuthorizationInput): Promise<OAuthAuthorizationSession> {
      const flowStore = await requireFlowStore()
      const root = assertResolvablePath(input.root, 'binding root')
      const profilePath = assertResolvablePath(input.profilePath, 'profile path')
      const redirectUri = assertUrl(input.redirectUri, 'redirect uri').toString()
      const profile = await options.getProfile(profilePath)
      const oauthConfig = parseOAuthProfileConfig(profile)
      if (!oauthConfig) {
        throw new AgentPwInputError(`Credential Profile '${profilePath}' has no OAuth configuration`)
      }

      const authorizationServer = await resolveAuthorizationServer(oauthConfig, options.customFetch)
      if (!authorizationServer.authorization_endpoint) {
        throw new AgentPwInputError(`Credential Profile '${profilePath}' is missing an authorization endpoint`)
      }

      const flowId = validateFlowId(undefined) ?? randomId() + randomId()
      const codeVerifier = oauth.generateRandomCodeVerifier()
      const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)
      const authorizationUrl = new URL(authorizationServer.authorization_endpoint)

      authorizationUrl.searchParams.set('client_id', oauthConfig.clientId)
      authorizationUrl.searchParams.set('redirect_uri', redirectUri)
      authorizationUrl.searchParams.set('response_type', 'code')
      authorizationUrl.searchParams.set('state', flowId)
      authorizationUrl.searchParams.set('code_challenge', codeChallenge)
      authorizationUrl.searchParams.set('code_challenge_method', 'S256')

      const scopes = toScopeString(input.scopes) ?? toScopeString(oauthConfig.scopes)
      if (scopes) {
        authorizationUrl.searchParams.set('scope', scopes)
      }

      for (const [key, value] of Object.entries(input.additionalParameters ?? {})) {
        authorizationUrl.searchParams.set(key, value)
      }

      const credentialPath = input.credentialPath === undefined
        ? undefined
        : assertResolvablePath(input.credentialPath, 'credential path')

      const flow: PendingFlow = {
        id: flowId,
        root,
        profilePath,
        credentialPath,
        redirectUri,
        codeVerifier,
        expiresAt: input.expiresAt ?? defaultExpiry(options.clock),
      }

      await flowStore.create(flow)

      return {
        flowId,
        authorizationUrl: authorizationUrl.toString(),
        expiresAt: flow.expiresAt,
        root,
        profilePath,
        credentialPath: flow.credentialPath,
      }
    },

    async completeAuthorization(input: OAuthCompleteAuthorizationInput): Promise<OAuthCompletionResult> {
      const flowStore = await requireFlowStore()
      const callbackUrl = assertUrl(input.callbackUri, 'callback uri')
      const flowId = callbackUrl.searchParams.get('state')
      if (!flowId) {
        throw new AgentPwInputError('OAuth callback is missing state')
      }

      const flow = await flowStore.get(flowId)
      if (!flow) {
        throw new AgentPwInputError(`Unknown OAuth flow '${flowId}'`)
      }
      if (flow.expiresAt.getTime() <= options.clock().getTime()) {
        await flowStore.delete(flow.id)
        throw new AgentPwInputError(`OAuth flow '${flow.id}' has expired`)
      }

      const profile = await options.getProfile(flow.profilePath)
      const oauthConfig = parseOAuthProfileConfig(profile)
      if (!(profile && oauthConfig)) {
        throw new AgentPwInputError(`Credential Profile '${flow.profilePath}' has no OAuth configuration`)
      }

      const authorizationServer = await resolveAuthorizationServer(oauthConfig, options.customFetch)
      const client = buildClient(oauthConfig)
      const clientAuthentication = buildClientAuthentication(oauthConfig)
      const validated = oauth.validateAuthResponse(authorizationServer, client, callbackUrl, flow.id)
      const tokenResponse = await oauth.authorizationCodeGrantRequest(
        authorizationServer,
        client,
        clientAuthentication,
        validated,
        flow.redirectUri,
        flow.codeVerifier,
        options.customFetch
          ? { [oauth.customFetch]: options.customFetch }
          : undefined,
      )
      const processed = await oauth.processAuthorizationCodeResponse(authorizationServer, client, tokenResponse)

      const credential = await options.putBinding({
        root: flow.root,
        profilePath: flow.profilePath,
        credentialPath: flow.credentialPath,
        auth: {
          kind: 'oauth',
          provider: profile.provider,
        },
        secret: oauthSecretFromTokenResponse(profile, processed),
      })

      await flowStore.complete(flow.id)

      return {
        binding: {
          root: flow.root,
          profilePath: flow.profilePath,
        },
        credentialPath: credential.path,
        credential,
      }
    },

    async refreshCredential(input: OAuthRefreshInput) {
      const resolved = await options.resolveBinding({
        root: input.root,
        profilePath: input.profilePath,
        credentialPath: input.credentialPath,
        refresh: false,
      })
      return refreshResolvedCredential(resolved, input)
    },

    async disconnect(input: OAuthDisconnectInput) {
      const resolved = await options.resolveBinding({
        root: input.root,
        profilePath: input.profilePath,
        credentialPath: input.credentialPath,
        refresh: false,
      })
      if (!resolved) {
        return false
      }

      const profile = resolved.profile ?? await options.getProfile(input.profilePath)
      const oauthConfig = parseOAuthProfileConfig(profile)
      const revokeMode = input.revoke ?? 'refresh_token'
      if (oauthConfig) {
        const authorizationServer = await resolveAuthorizationServer(oauthConfig, options.customFetch)
        if (authorizationServer.revocation_endpoint) {
          const client = buildClient(oauthConfig)
          const clientAuthentication = buildClientAuthentication(oauthConfig)

          if ((revokeMode === 'refresh_token' || revokeMode === 'both') && resolved.secret.oauth?.refreshToken) {
            const response = await oauth.revocationRequest(
              authorizationServer,
              client,
              clientAuthentication,
              resolved.secret.oauth.refreshToken,
              options.customFetch
                ? {
                    [oauth.customFetch]: options.customFetch,
                    additionalParameters: { token_type_hint: 'refresh_token' },
                  }
                : {
                    additionalParameters: { token_type_hint: 'refresh_token' },
                  },
            )
            await oauth.processRevocationResponse(response)
          }

          if ((revokeMode === 'access_token' || revokeMode === 'both') && resolved.secret.oauth?.accessToken) {
            const response = await oauth.revocationRequest(
              authorizationServer,
              client,
              clientAuthentication,
              resolved.secret.oauth.accessToken,
              options.customFetch
                ? {
                    [oauth.customFetch]: options.customFetch,
                    additionalParameters: { token_type_hint: 'access_token' },
                  }
                : {
                    additionalParameters: { token_type_hint: 'access_token' },
                  },
            )
            await oauth.processRevocationResponse(response)
          }
        }
      }

      return options.deleteCredential(resolved.path)
    },

    createWebHandlers(
      optionsForHandlers: {
        callbackPath?: string
        success?(result: OAuthCompletionResult, request: Request): Response | Promise<Response>
        error?(error: unknown, request: Request): Response | Promise<Response>
      } = {},
    ): OAuthWebHandlers {
      const callbackPath = optionsForHandlers.callbackPath ?? '/oauth/callback'

      return {
        start: async (request, input) => {
          const session = await this.startAuthorization({
            ...input,
            redirectUri: input.redirectUri ?? resolveRedirectUri(request, callbackPath),
          })
          return Response.redirect(session.authorizationUrl, 302)
        },

        callback: async request => {
          try {
            const result = await this.completeAuthorization({
              callbackUri: request.url,
            })
            if (optionsForHandlers.success) {
              return optionsForHandlers.success(result, request)
            }
            return defaultSuccessResponse()
          } catch (error) {
            if (optionsForHandlers.error) {
              return optionsForHandlers.error(error, request)
            }
            return defaultErrorResponse(error)
          }
        },
      }
    },

    createClientMetadataDocument(input: CimdDocumentInput): CimdDocument {
      const clientId = assertUrl(input.clientId, 'client id').toString()
      if (input.redirectUris.length === 0) {
        throw new AgentPwInputError('CIMD requires at least one redirect URI')
      }

      return {
        client_id: clientId,
        redirect_uris: input.redirectUris.map(uri => assertUrl(uri, 'redirect uri').toString()),
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_method: input.tokenEndpointAuthMethod ?? 'none',
        client_name: input.clientName,
        scope: toScopeString(input.scope),
        jwks_uri: input.jwksUri ? assertUrl(input.jwksUri, 'jwks uri').toString() : undefined,
        jwks: input.jwks,
        token_endpoint_auth_signing_alg: input.tokenEndpointAuthSigningAlg,
      }
    },

    createClientMetadataResponse(input: CimdDocumentInput) {
      return new Response(JSON.stringify(this.createClientMetadataDocument(input), null, 2), {
        status: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'public, max-age=300',
        },
      })
    },
  }
}
