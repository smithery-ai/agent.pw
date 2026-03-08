import { index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema'
import { bytea, jsonb } from './types'

export const credentials = agentpwSchema.table('credentials', {
  host: text('host').notNull(),
  slug: text('slug').primaryKey(),
  auth: jsonb<Record<string, unknown>>()('auth').notNull(),
  secret: bytea('secret').notNull(),
  execSelectors: jsonb<Record<string, string>>()('exec_selectors').notNull(),
  adminSelectors: jsonb<Record<string, string>>()('admin_selectors').notNull(),
  execSelectorPairs: text('exec_selector_pairs').array().notNull(),
  adminSelectorPairs: text('admin_selector_pairs').array().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, table => [
  index('credentials_host_idx').on(table.host),
  index('credentials_exec_selector_pairs_idx').using('gin', table.execSelectorPairs),
  index('credentials_admin_selector_pairs_idx').using('gin', table.adminSelectorPairs),
])
