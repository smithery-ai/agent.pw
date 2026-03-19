import {
  index,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { authOauthClients, authUsers } from './better-auth.js'
import { jsonb } from './types.js'

export const authDelegationGrants = agentpwSchema.table('auth_delegation_grant', {
  id: text('id').primaryKey(),
  clientId: text('client_id')
    .notNull()
    .references(() => authOauthClients.clientId, { onDelete: 'cascade' }),
  userId: text('user_id')
    .notNull()
    .references(() => authUsers.id, { onDelete: 'cascade' }),
  orgId: text('org_id'),
  scopes: text('scopes').array().notNull(),
  authorizationDetails: jsonb<unknown>()('authorization_details'),
  mayAct: jsonb<unknown>()('may_act'),
  grantedBy: text('granted_by').notNull().default('auto'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  revokedAt: timestamp('revoked_at'),
}, table => ({
  clientIdx: index('auth_delegation_grant_client_idx').on(table.clientId),
  userIdx: index('auth_delegation_grant_user_idx').on(table.userId),
  clientUserUniqueIdx: uniqueIndex('auth_delegation_grant_client_user_unique')
    .on(table.clientId, table.userId),
}))

export const authDelegationTokens = agentpwSchema.table('auth_delegation_token', {
  id: text('id').primaryKey(),
  grantId: text('grant_id')
    .notNull()
    .references(() => authDelegationGrants.id, { onDelete: 'cascade' }),
  clientId: text('client_id')
    .notNull()
    .references(() => authOauthClients.clientId, { onDelete: 'cascade' }),
  userId: text('user_id')
    .notNull()
    .references(() => authUsers.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull(),
  scopes: text('scopes').array().notNull(),
  actor: text('actor'),
  authorizationDetails: jsonb<unknown>()('authorization_details'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at').notNull(),
  revokedAt: timestamp('revoked_at'),
}, table => ({
  tokenHashUniqueIdx: uniqueIndex('auth_delegation_token_token_hash_unique')
    .on(table.tokenHash),
  clientIdx: index('auth_delegation_token_client_idx').on(table.clientId),
  userIdx: index('auth_delegation_token_user_idx').on(table.userId),
  grantIdx: index('auth_delegation_token_grant_idx').on(table.grantId),
}))
