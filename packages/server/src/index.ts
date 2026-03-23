import { getPublicKeyHex } from './biscuit.js'
import { createAccessService } from './access.js'
import {
  deleteCredProfile,
  deleteCredential,
  getCredProfile,
  getCredProfilesByHostWithinRoot,
  getCredProfilesByProviderWithinRoot,
  getCredential,
  getCredentialsByProfileWithinRoot,
  listCredProfiles,
  listCredentials,
  moveCredential,
  upsertCredProfile,
  upsertCredential,
} from './db/queries.js'
import { AgentPwConflictError, AgentPwInputError } from './errors.js'
import { decryptCredentials, deriveEncryptionKey, encryptCredentials } from './lib/credentials-crypto.js'
import { createLogger } from './lib/logger.js'
import { deriveDisplayName } from './lib/utils.js'
import { createInMemoryFlowStore, createOAuthService } from './oauth.js'
import {
  canonicalizePath,
  credentialName,
  isAncestorOrEqual,
  joinCredentialPath,
  validatePath,
} from './paths.js'
import type {
  AgentPw,
  AgentPwOptions,
  CredentialProfileRecord,
  CredentialRecord,
  CredentialSummary,
  ResolvedCredential,
} from './types.js'

function toProfileRecord(row: {
  path: string
  host: string[]
  auth: Record<string, unknown> | null
  oauthConfig: Record<string, unknown> | null
  displayName: string | null
  description: string | null
  createdAt: Date
  updatedAt: Date
}): CredentialProfileRecord {
  return {
    ...row,
    provider: credentialName(row.path),
  }
}

function resolveSingleMatch<T extends { path: string }>(
  matches: T[],
  description: string,
): T | undefined {
  if (matches.length === 0) {
    return undefined
  }

  const topDepth = matches
    .map(match => match.path.split('/').filter(Boolean).length)
    .reduce((max, depth) => Math.max(max, depth), 0)
  const conflicts = matches.filter(match => match.path.split('/').filter(Boolean).length === topDepth)
  if (conflicts.length > 1) {
    throw new AgentPwConflictError(
      `${description} resolves to multiple candidates at the same depth: ${conflicts.map(conflict => conflict.path).join(', ')}`,
    )
  }

  return conflicts[0]
}

function assertPath(path: string, label: string) {
  const normalized = canonicalizePath(path)
  if (!validatePath(normalized) || normalized === '/') {
    throw new AgentPwInputError(`Invalid ${label} '${path}'`)
  }
  return normalized
}

function normalizeRoot(root: string, label: string) {
  const normalized = canonicalizePath(root)
  if (!validatePath(normalized)) {
    throw new AgentPwInputError(`Invalid ${label} '${root}'`)
  }
  return normalized
}

async function decryptCredentialRecord(
  encryptionKey: string,
  row: {
    profilePath: string
    host: string | null
    path: string
    auth: Record<string, unknown>
    secret: Buffer
    createdAt: Date
    updatedAt: Date
  },
): Promise<CredentialRecord> {
  return {
    profilePath: row.profilePath,
    host: row.host,
    path: row.path,
    auth: row.auth,
    secret: await decryptCredentials(encryptionKey, row.secret),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  }
}

function assertBindingInput(input: {
  root: string
  profilePath: string
}) {
  return {
    root: normalizeRoot(input.root, 'binding root'),
    profilePath: assertPath(input.profilePath, 'profile path'),
  }
}

function resolveBindingCredentialPath(input: {
  root: string
  profilePath: string
  credentialPath?: string
}) {
  const credentialPath = input.credentialPath
    ? assertPath(input.credentialPath, 'credential path')
    : joinCredentialPath(input.root, credentialName(input.profilePath))

  if (!isAncestorOrEqual(input.root, credentialPath)) {
    throw new AgentPwInputError(`Credential path '${credentialPath}' is outside root '${input.root}'`)
  }

  return credentialPath
}

export async function createAgentPw(options: AgentPwOptions): Promise<AgentPw> {
  const encryptionKey = options.encryptionKey ?? await deriveEncryptionKey(options.biscuitPrivateKey)
  const logger = options.logger ?? createLogger('agentpw').logger
  const clock = options.clock ?? (() => new Date())
  const publicKeyHex = getPublicKeyHex(options.biscuitPrivateKey)
  const oauth = createOAuthService({
    flowStore: options.flowStore ?? createInMemoryFlowStore(),
    clock,
  })

  const profiles: AgentPw['profiles'] = {
    async resolve(input) {
      const root = canonicalizePath(input.root)
      if (!validatePath(root)) {
        throw new AgentPwInputError(`Invalid root '${input.root}'`)
      }

      let matches = input.provider
        ? await getCredProfilesByProviderWithinRoot(options.db, input.provider, root)
        : input.host
          ? await getCredProfilesByHostWithinRoot(options.db, input.host, root)
          : []

      const { host } = input
      if (host) {
        matches = matches.filter(profile => profile.host.includes(host))
      }

      const selected = resolveSingleMatch(matches, 'Credential Profile')
      return selected ? toProfileRecord(selected) : null
    },

    async get(path) {
      const selected = await getCredProfile(options.db, assertPath(path, 'profile path'))
      return selected ? toProfileRecord(selected) : null
    },

    async list(query = {}) {
      const rows = await listCredProfiles(options.db, {
        root: query.root ? normalizeRoot(query.root, 'profile root') : '/',
      })
      return rows.map(toProfileRecord)
    },

    async put(path, data) {
      const profilePath = assertPath(path, 'profile path')
      if (data.host.length === 0) {
        throw new AgentPwInputError('Credential Profile host list cannot be empty')
      }

      await upsertCredProfile(options.db, profilePath, {
        host: data.host,
        auth: data.auth,
        oauthConfig: data.oauthConfig,
        displayName: data.displayName ?? deriveDisplayName(String(data.host[0])),
        description: data.description,
      })

      const stored = await getCredProfile(options.db, profilePath)
      if (!stored) {
        throw new Error(`Failed to persist Credential Profile '${profilePath}'`)
      }
      return toProfileRecord(stored)
    },

    delete(path) {
      return deleteCredProfile(options.db, assertPath(path, 'profile path'))
    },
  }

  async function resolveBinding(
    input: {
      root: string
      profilePath: string
      credentialPath?: string
    },
  ): Promise<ResolvedCredential | null> {
    const binding = assertBindingInput(input)
    const profile = await profiles.get(binding.profilePath)
    const exactPath = input.credentialPath
      ? resolveBindingCredentialPath({
          ...binding,
          credentialPath: input.credentialPath,
        })
      : null

    if (exactPath) {
      const exact = await getCredential(options.db, exactPath)
      if (!exact || exact.profilePath !== binding.profilePath) {
        return null
      }

      const decrypted = await decryptCredentialRecord(encryptionKey, exact)
      return { ...decrypted, profile }
    }

    const matches = await getCredentialsByProfileWithinRoot(options.db, binding.profilePath, binding.root)
    const selected = resolveSingleMatch(matches, 'Credential')
    if (!selected) {
      return null
    }

    const decrypted = await decryptCredentialRecord(encryptionKey, selected)
    return { ...decrypted, profile }
  }

  async function putCredential(path: string, input: {
    profilePath: string
    host?: string | null
    auth?: Record<string, unknown>
    secret: CredentialRecord['secret'] | Buffer
  }) {
    const credentialPath = assertPath(path, 'credential path')
    const profilePath = assertPath(input.profilePath, 'profile path')
    const secret = Buffer.isBuffer(input.secret)
      ? input.secret
      : await encryptCredentials(encryptionKey, input.secret)

    await upsertCredential(options.db, {
      profilePath,
      host: input.host ?? null,
      path: credentialPath,
      auth: input.auth ?? { kind: 'opaque' },
      secret,
    })

    const stored = await getCredential(options.db, credentialPath)
    if (!stored) {
      throw new Error(`Failed to persist Credential '${credentialPath}'`)
    }

    return decryptCredentialRecord(encryptionKey, stored)
  }

  const bindings: AgentPw['bindings'] = {
    resolve(input) {
      return resolveBinding(input)
    },

    async resolveHeaders(input) {
      const resolved = await resolveBinding(input)
      return resolved?.secret.headers ?? {}
    },

    async put(input) {
      const binding = assertBindingInput(input)
      const profile = await profiles.get(binding.profilePath)
      const credentialPath = resolveBindingCredentialPath({
        ...binding,
        credentialPath: input.credentialPath,
      })
      const host = input.host ?? profile?.host[0] ?? null
      const credential = await putCredential(credentialPath, {
        profilePath: binding.profilePath,
        host,
        auth: input.auth,
        secret: input.secret,
      })

      return {
        ...credential,
        profile,
      }
    },
  }

  const credentials: AgentPw['credentials'] = {
    async resolve(input) {
      const resolved = await resolveBinding(input)
      if (!resolved) {
        return null
      }

      const { profile, ...credential } = resolved
      return credential
    },

    async get(path) {
      const selected = await getCredential(options.db, assertPath(path, 'credential path'))
      return selected ? decryptCredentialRecord(encryptionKey, selected) : null
    },

    async list(query = {}) {
      const rows = await listCredentials(options.db, {
        root: query.root ? normalizeRoot(query.root, 'credential root') : '/',
      })
      return rows.map<CredentialSummary>(row => ({
        profilePath: row.profilePath,
        host: row.host,
        path: row.path,
        auth: row.auth,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      }))
    },

    put(path, input) {
      return putCredential(path, input)
    },

    move(fromPath, toPath) {
      return moveCredential(
        options.db,
        assertPath(fromPath, 'source path'),
        assertPath(toPath, 'target path'),
      )
    },

    delete(path) {
      return deleteCredential(options.db, assertPath(path, 'credential path'))
    },
  }

  const access = createAccessService({
    ...options,
    encryptionKey,
    logger,
    clock,
    publicKeyHex,
  })

  logger.debug({ publicKeyHex }, 'agent.pw initialized')

  return {
    profiles,
    bindings,
    credentials,
    oauth,
    access,
  }
}

export type * from './types.js'
export { AgentPwConflictError, AgentPwInputError } from './errors.js'
