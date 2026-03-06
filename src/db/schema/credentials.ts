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
    orgId: text('org_id').notNull(),
    slug: text('slug').notNull(), // service slug (references services.slug)
    label: text('label').notNull().default('default'), // multiple credentials per service
    encryptedCredentials: bytea('encrypted_credentials').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
  },
  t => [primaryKey({ columns: [t.orgId, t.slug, t.label] })],
)
