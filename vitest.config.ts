import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/vitest.setup.ts'],
    exclude: ['**/node_modules/**'],
    coverage: {
      provider: 'v8',
      all: true,
      include: ['packages/server/src/**/*.ts'],
      exclude: ['packages/server/src/core/types.ts', 'packages/server/src/db/schema/**'],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
})
