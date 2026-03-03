import { serve } from '@hono/node-server'
import { createApp } from './index'
import { createDb } from './db/index'

const port = parseInt(process.env.PORT ?? '3000', 10)
const databaseUrl = process.env.DATABASE_URL

if (!databaseUrl) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}

const db = createDb(databaseUrl)

const app = createApp({
  db,
  biscuitPrivateKey: process.env.BISCUIT_PRIVATE_KEY ?? '',
  baseUrl: process.env.BASE_URL ?? `http://localhost:${port}`,
  encryptionKey: process.env.ENCRYPTION_KEY ?? '',
  awsRegion: process.env.AWS_REGION,
})

console.log(`Warden listening on http://localhost:${port}`)

serve({ fetch: app.fetch, port })
