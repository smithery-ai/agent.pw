import { text, timestamp } from 'drizzle-orm/pg-core'
import { agentpwSchema } from './agentpw-schema.js'
import { jsonb } from './types.js'

export interface VerificationResult {
  name: string
  pass: boolean
  ms: number
  detail: string
}

export const verification = agentpwSchema.table('verification', {
  path: text('path').primaryKey(),
  verifiedStatus: text('verified_status'),
  verifiedNote: text('verified_note'),
  results: jsonb<VerificationResult[]>()('results'),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
