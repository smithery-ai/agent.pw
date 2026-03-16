import { defineConfig } from 'drizzle-kit'

const databaseUrl = process.env.DATABASE_URL

if (!databaseUrl) {
  throw new Error('DATABASE_URL is required to load drizzle.config.ts')
}

export default defineConfig({
  schema: './packages/server/src/db/schema/*',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: databaseUrl,
  },
  schemaFilter: ['agentpw'],
  migrations: {
    schema: 'agentpw',
  },
})
