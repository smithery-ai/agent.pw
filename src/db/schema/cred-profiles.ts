import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'

export const credProfiles = agentpwSchema.table('cred_profiles', {
  slug: text('slug').primaryKey(),
  host: text('host').notNull(), // JSON: string[] of hostnames this profile applies to
  auth: text('auth'), // JSON: { kind: "oauth", authorizeUrl, tokenUrl, scopes, ... } or { kind: "headers", fields: [...] }
  managedOauth: text('managed_oauth'), // JSON: { clientId, encryptedClientSecret } — managed only
  displayName: text('display_name'),
  description: text('description'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
