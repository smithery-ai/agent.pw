import { text, timestamp } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'
import { bytea } from './types'

export const webhookRegistrations = wardenSchema.table('webhook_registrations', {
  id: text('id').primaryKey(), // random hex, doubles as hookPath
  orgId: text('org_id').notNull(),
  service: text('service').notNull(), // hostname: api.github.com
  callbackUrl: text('callback_url').notNull(),
  encryptedWebhookSecret: bytea('encrypted_webhook_secret'), // upstream signing secret
  metadata: text('metadata'), // JSON
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
})
