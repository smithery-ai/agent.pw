import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { bytea } from './types'

export const credentials = agentpwSchema.table('credentials', {
  id: text('id').primaryKey(),
  host: text('host').notNull(), // target hostname this credential authenticates against
  slug: text('slug').notNull().unique(), // unique user-facing alias (auto-generated or user-specified)
  auth: text('auth').notNull(), // JSON: { kind: "oauth" } or { kind: "headers", headers: {...} }
  secret: bytea('secret').notNull(), // encrypted token / key material
  execPolicy: text('exec_policy'), // Biscuit datalog: who can use this credential through the proxy
  adminPolicy: text('admin_policy'), // Biscuit datalog: who can create, replace, share, or revoke it
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
