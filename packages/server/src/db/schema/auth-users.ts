import { boolean, index, text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'

export const authUsers = agentpwSchema.table('auth_users', {
  id: text('id').primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  email: text('email').notNull(),
  emailVerified: boolean('email_verified').default(false).notNull(),
  name: text('name').notNull(),
  image: text('image'),
}, table => [
  index('auth_users_email_idx').on(table.email),
])
