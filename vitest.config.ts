import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/setup.ts'],
    exclude: ['**/node_modules/**', '.workers-biscuit-pr/**'],
    coverage: {
      provider: 'v8',
      all: true,
      include: ['src/db/**/*.ts', 'src/lib/**/*.ts'],
      exclude: ['src/db/index.ts', 'src/db/migrate-local.ts', 'src/lib/logger.ts', 'src/lib/oauth-refresh.ts', 'src/lib/dns.ts', 'src/lib/utils.ts'],
      thresholds: {
        lines: 70,
        functions: 60,
        branches: 75,
        statements: 70,
      },
    },
  },
})
