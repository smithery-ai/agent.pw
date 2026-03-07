import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  schema: './packages/server/src/db/schema/*',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL as string,
  },
  schemaFilter: ['agentpw'],
  migrations: {
    schema: 'agentpw',
  },
})
