import {
  authorizeRequest,
  extractTokenExpiry,
  extractTokenFacts,
  getPublicKeyHex,
  getRevocationIds,
  hashToken,
  mintToken,
  restrictToken,
} from './biscuit.js'
import {
  createIssuedToken,
  getIssuedTokenByHash,
  isRevoked,
  markIssuedTokenUsedBestEffort,
  revokeIssuedTokenByIdUnscoped,
} from './db/queries.js'
import { AgentPwInputError } from './errors.js'
import { randomId } from './lib/utils.js'
import { hasRightForPath } from './rights.js'
import type {
  AccessInspection,
  AgentPwOptions,
  AuthorizeAccessInput,
  AuthorizationResult,
  MintAccessInput,
  TokenConstraint,
} from './types.js'

function buildOwnerFacts(input: MintAccessInput) {
  const owner = input.owner
  const subject = owner?.subject ?? owner?.userId ?? owner?.orgId ?? 'agentpw'
  const facts: string[] = []

  if (owner?.orgId) {
    facts.push(`org_id("${owner.orgId}");`)
  }
  if (owner?.homePath) {
    facts.push(`home_path("${owner.homePath}");`)
  }
  for (const scope of owner?.scopes ?? []) {
    facts.push(`scope("${scope}");`)
  }

  return { subject, facts }
}

async function isTokenRevoked(
  db: AgentPwOptions['db'],
  revocationIds: string[],
) {
  for (const revocationId of revocationIds) {
    if (await isRevoked(db, revocationId)) {
      return true
    }
  }
  return false
}

export function createAccessService(options: AgentPwOptions & {
  publicKeyHex: string
  clock: () => Date
}) {
  return {
    async mint(input: MintAccessInput) {
      const normalizedConstraints = input.constraints ?? []
      const { subject, facts } = buildOwnerFacts(input)
      const baseToken = mintToken(
        options.biscuitPrivateKey,
        subject,
        input.rights,
        facts,
      )
      const token = normalizedConstraints.length > 0
        ? restrictToken(baseToken, options.publicKeyHex, normalizedConstraints)
        : baseToken
      const id = randomId()
      const revocationIds = getRevocationIds(token, options.publicKeyHex)
      const expiresAt = extractTokenExpiry(token, options.publicKeyHex)

      await createIssuedToken(options.db, {
        id,
        ownerUserId: input.owner?.userId ?? null,
        orgId: input.owner?.orgId ?? null,
        name: input.owner?.name ?? null,
        tokenHash: await hashToken(token),
        revocationIds,
        rights: input.rights,
        constraints: normalizedConstraints,
        expiresAt,
      })

      return {
        id,
        token,
        expiresAt,
        revocationIds,
      }
    },

    async inspect(token: string): Promise<AccessInspection> {
      const facts = extractTokenFacts(token, options.publicKeyHex)
      const tokenHash = await hashToken(token)
      const tracked = await getIssuedTokenByHash(options.db, tokenHash)
      let revocationIds: string[] = []
      let expiresAt: Date | null = null
      try {
        revocationIds = getRevocationIds(token, options.publicKeyHex)
        expiresAt = extractTokenExpiry(token, options.publicKeyHex)
      } catch {}
      const revoked = revocationIds.length > 0
        ? await isTokenRevoked(options.db, revocationIds)
        : false
      const valid = Boolean(facts.userId || facts.orgId || facts.rights.length > 0) && !revoked

      return {
        valid,
        rights: facts.rights,
        userId: facts.userId,
        orgId: facts.orgId,
        homePath: facts.homePath,
        scopes: facts.scopes,
        expiresAt,
        revoked,
        revocationIds,
        trackedTokenId: tracked?.id ?? null,
      }
    },

    restrict(token: string, constraints: TokenConstraint[]) {
      return restrictToken(token, options.publicKeyHex, constraints)
    },

    async revoke(id: string, reason?: string) {
      const revoked = await revokeIssuedTokenByIdUnscoped(options.db, id, reason)
      return revoked !== null
    },

    async authorize(input: AuthorizeAccessInput): Promise<AuthorizationResult> {
      if (!input.path.startsWith('/')) {
        throw new AgentPwInputError(`Invalid path '${input.path}'`)
      }
      if (!input.root.startsWith('/')) {
        throw new AgentPwInputError(`Invalid root '${input.root}'`)
      }

      const inspection = await this.inspect(input.token)
      if (!inspection.valid) {
        return {
          authorized: false,
          error: inspection.revoked ? 'Token has been revoked' : 'Token is invalid',
        }
      }

      const action = input.action ?? 'credential.use'
      if (!hasRightForPath(inspection.rights, action, input.path)) {
        return {
          authorized: false,
          error: `Token is missing '${action}' for '${input.path}'`,
          facts: {
            rights: inspection.rights,
            userId: inspection.userId,
            orgId: inspection.orgId,
            homePath: inspection.homePath,
            scopes: inspection.scopes,
          },
          trackedTokenId: inspection.trackedTokenId,
        }
      }

      const authorizerResult = authorizeRequest(
        input.token,
        options.publicKeyHex,
        input.host,
        input.method,
        input.path,
        {
          action,
          host: input.host,
          requestedRoot: input.root,
        },
      )

      if (!authorizerResult.authorized) {
        return {
          authorized: false,
          error: authorizerResult.error,
          facts: {
            rights: inspection.rights,
            userId: inspection.userId,
            orgId: inspection.orgId,
            homePath: inspection.homePath,
            scopes: inspection.scopes,
          },
          trackedTokenId: inspection.trackedTokenId,
        }
      }

      await markIssuedTokenUsedBestEffort(options.db, await hashToken(input.token), options.clock())

      return {
        authorized: true,
        facts: {
          rights: inspection.rights,
          userId: inspection.userId,
          orgId: inspection.orgId,
          homePath: inspection.homePath,
          scopes: inspection.scopes,
        },
        trackedTokenId: inspection.trackedTokenId,
      }
    },
  }
}

export {
  extractTokenFacts,
  extractTokenExpiry,
  getPublicKeyHex,
  getRevocationIds,
  hashToken,
  mintToken,
  restrictToken,
}
