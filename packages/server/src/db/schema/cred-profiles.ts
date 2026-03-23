import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { jsonb, ltree } from './types.js'

export const credProfiles = agentpwSchema.table('cred_profiles', {
  path: ltree('path').primaryKey(),
  host: jsonb<string[]>()('host').notNull(),
  auth: jsonb<Record<string, unknown>>()('auth'),
  oauthConfig: jsonb<Record<string, unknown>>()('oauth_config'),
  displayName: text('display_name'),
  description: text('description'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  index('cred_profiles_path_idx').on(table.path),
  index('cred_profiles_host_idx').using('gin', table.host),
])
