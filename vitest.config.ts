import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      all: true,
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: ['src/server.ts', 'src/ui.tsx', 'src/types.ts', 'src/db/index.ts', 'src/discovery/**'],
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
})
