import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'

export const authFlowMethodEnum = agentpwSchema.enum('auth_flow_method', ['oauth', 'api_key'])
export const authFlowStatusEnum = agentpwSchema.enum('auth_flow_status', ['pending', 'completed'])

export const authFlows = agentpwSchema.table('auth_flows', {
  id: text('id').primaryKey(),
  slug: text('slug').notNull(),
  method: authFlowMethodEnum('method').notNull(),
  status: authFlowStatusEnum('status').notNull().default('pending'),
  codeVerifier: text('code_verifier'),
  execPolicy: text('exec_policy'),
  token: text('token'),
  identity: text('identity'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
