import { text, timestamp, integer, primaryKey } from 'drizzle-orm/pg-core'
import { wardenSchema } from './warden-schema'

export const docPages = wardenSchema.table(
  'doc_pages',
  {
    hostname: text('hostname').notNull(),
    path: text('path').notNull(),
    content: text('content'),
    status: text('status').notNull().default('skeleton'),
    generatedAt: timestamp('generated_at').defaultNow().notNull(),
    ttlDays: integer('ttl_days').notNull().default(7),
  },
  t => [primaryKey({ columns: [t.hostname, t.path] })],
)
