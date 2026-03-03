import { text, timestamp, primaryKey, customType } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

const bytea = customType<{ data: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

export const credentials = wardenSchema.table(
  'credentials',
  {
    vaultSlug: text('vault_slug').notNull(),
    service: text('service').notNull(),
    identity: text('identity'), // informational — resolved via whoami
    encryptedCredentials: bytea('encrypted_credentials').notNull(),
    metadata: text('metadata'), // JSON
    expiresAt: timestamp('expires_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  t => [primaryKey({ columns: [t.vaultSlug, t.service] })],
)
