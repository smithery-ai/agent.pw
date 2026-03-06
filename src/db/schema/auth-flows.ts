import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'

export const authFlows = agentpwSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  slug: text('slug').notNull(), // cred_profile slug or host
  method: text('method').notNull(), // "oauth", "headers"
  status: text('status').notNull().default('pending'),
  codeVerifier: text('code_verifier'), // PKCE verifier for OAuth
  execPolicy: text('exec_policy'), // Biscuit policy to set on the resulting credential
  token: text('token'), // minted Biscuit token (set on completion)
  identity: text('identity'), // user identity from provider (set on completion)
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
