import { index, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core'
import type { TokenConstraint, TokenRight } from '../../types.js'
import { agentpwSchema } from './agentpw-schema.js'
import { jsonb } from './types.js'

export const issuedTokens = agentpwSchema.table('issued_tokens', {
  id: text('id').primaryKey(),
  ownerUserId: text('owner_user_id'),
  orgId: text('org_id'),
  name: text('name'),
  tokenHash: text('token_hash').notNull(),
  revocationIds: jsonb<string[]>()('revocation_ids').notNull(),
  rights: jsonb<TokenRight[]>()('rights').notNull(),
  constraints: jsonb<TokenConstraint[]>()('constraints').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at'),
  lastUsedAt: timestamp('last_used_at'),
  revokedAt: timestamp('revoked_at'),
  revokeReason: text('revoke_reason'),
}, table => [
  uniqueIndex('issued_tokens_token_hash_idx').on(table.tokenHash),
  index('issued_tokens_owner_user_created_idx').on(table.ownerUserId, table.createdAt),
  index('issued_tokens_org_created_idx').on(table.orgId, table.createdAt),
])
