import { text, timestamp, primaryKey, customType } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

const bytea = customType<{ data: Buffer }>({
  dataType() {
    return 'bytea'
  },
})

export const oauthApps = wardenSchema.table(
  'oauth_apps',
  {
    orgId: text('org_id').notNull(),
    service: text('service').notNull(),
    clientId: text('client_id').notNull(),
    encryptedClientSecret: bytea('encrypted_client_secret'),
    scopes: text('scopes'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  t => [primaryKey({ columns: [t.orgId, t.service] })],
)
