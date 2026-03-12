import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { credProfiles } from './cred-profiles.js'

export const authFlowMethodEnum = agentpwSchema.enum('auth_flow_method', ['oauth', 'api_key'])
export const authFlowStatusEnum = agentpwSchema.enum('auth_flow_status', ['pending', 'completed'])

export const authFlows = agentpwSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  profilePath: text('profile_path').references(() => credProfiles.path),
  method: authFlowMethodEnum('method').notNull(),
  status: authFlowStatusEnum('status').notNull().default('pending'),
  codeVerifier: text('code_verifier'),
  scopePath: text('scope_path'),
  token: text('token'),
  identity: text('identity'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
