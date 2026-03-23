import type { Account, BetterAuthPlugin, GenericEndpointContext } from 'better-auth'
import type { AgentPw, CredentialProfileRecord } from '../types.js'
import { credentialName, joinCredentialPath, validatePath } from '../paths.js'
import { isRecord } from '../lib/utils.js'
import type { StoredCredentials } from '../lib/credentials-crypto.js'
import { authAccounts } from '../db/schema/auth-accounts.js'
import { authSessions } from '../db/schema/auth-sessions.js'
import { authUsers } from '../db/schema/auth-users.js'
import { authVerifications } from '../db/schema/auth-verifications.js'

export const betterAuthSchema = {
  user: authUsers,
  session: authSessions,
  account: authAccounts,
  verification: authVerifications,
}

export interface AgentPwBetterAuthTarget {
  root: string
  credentialPath?: string
  provider?: string
  profilePath: string
  host?: string
  auth?: Record<string, unknown>
}

export interface AgentPwBetterAuthPluginOptions {
  agentPw: Pick<AgentPw, 'profiles' | 'bindings'>
  selectCredential(input: {
    account: Account
    context: GenericEndpointContext | null
  }): Promise<AgentPwBetterAuthTarget | null> | AgentPwBetterAuthTarget | null
  buildStoredCredentials?(input: {
    account: Account
    profile: CredentialProfileRecord | null
    target: AgentPwBetterAuthTarget
  }): StoredCredentials
}

function isAccount(value: unknown): value is Account {
  return isRecord(value)
    && typeof value.providerId === 'string'
    && typeof value.accountId === 'string'
    && typeof value.userId === 'string'
}

function stringValue(value: unknown) {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function defaultStoredCredentials(input: {
  account: Account
  profile: CredentialProfileRecord | null
}) {
  const oauthConfig = isRecord(input.profile?.oauthConfig)
    ? input.profile.oauthConfig
    : null
  const accessToken = stringValue(input.account.accessToken)
  const refreshToken = stringValue(input.account.refreshToken)
  const expiresAt =
    input.account.accessTokenExpiresAt instanceof Date
      ? input.account.accessTokenExpiresAt.toISOString()
      : undefined
  const headers: Record<string, string> = accessToken
    ? { Authorization: `Bearer ${accessToken}` }
    : {}

  return {
    headers,
    oauth: {
      accessToken,
      refreshToken,
      expiresAt,
      tokenUrl: stringValue(oauthConfig?.tokenUrl),
      clientId: stringValue(oauthConfig?.clientId),
      clientSecret: stringValue(oauthConfig?.clientSecret),
      scopes: stringValue(input.account.scope) ?? stringValue(oauthConfig?.scopes),
    },
  } satisfies StoredCredentials
}

async function syncAccountToCredential(
  options: AgentPwBetterAuthPluginOptions,
  account: Account | null,
  context: GenericEndpointContext | null,
) {
  if (!account) {
    return
  }

  const target = await options.selectCredential({ account, context })
  if (!target) {
    return
  }
  if (!validatePath(target.root) || target.root === '/') {
    throw new Error(`Invalid binding root '${target.root}'`)
  }

  if (!validatePath(target.profilePath) || target.profilePath === '/') {
    throw new Error(`Invalid profile path '${target.profilePath}'`)
  }
  const profile = await options.agentPw.profiles.get(target.profilePath)
  const credentialPath =
    target.credentialPath
    ?? joinCredentialPath(target.root, credentialName(target.profilePath))
  const host = target.host ?? profile?.host[0] ?? null

  const secret = options.buildStoredCredentials
    ? options.buildStoredCredentials({ account, profile, target })
    : defaultStoredCredentials({ account, profile })

  await options.agentPw.bindings.put({
    root: target.root,
    profilePath: target.profilePath,
    credentialPath,
    host,
    auth: target.auth ?? {
      kind: 'oauth',
      providerId: account.providerId,
      accountId: account.accountId,
      userId: account.userId,
    },
    secret,
  })
}

export function createAgentPwBetterAuthPlugin(
  options: AgentPwBetterAuthPluginOptions,
): BetterAuthPlugin {
  return {
    id: 'agentpw',
    init() {
      return {
        options: {
          databaseHooks: {
            account: {
              create: {
                async after(account, context) {
                  await syncAccountToCredential(options, account, context)
                },
              },
              update: {
                async after(account, context) {
                  if (!isAccount(account)) {
                    return
                  }
                  await syncAccountToCredential(options, account, context)
                },
              },
            },
          },
        },
      }
    },
  }
}
