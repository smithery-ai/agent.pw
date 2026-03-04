import { text, jsonb, timestamp, primaryKey, customType } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

const bytea = customType<{ data: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

export const credentials = wardenSchema.table(
  'credentials',
  {
    orgId: text('org_id').notNull(),
    service: text('service').notNull(),
    slug: text('slug').notNull().default('default'),
    encryptedCredentials: bytea('encrypted_credentials').notNull(),
    tags: jsonb('tags').$type<Record<string, string>>(),
    expiresAt: timestamp('expires_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  t => [primaryKey({ columns: [t.orgId, t.service, t.slug] })],
)
