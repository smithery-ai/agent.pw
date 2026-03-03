import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: ['src/server.ts', 'src/ui.tsx', 'src/types.ts', 'src/db/index.ts', 'src/discovery/**'],
    },
  },
})
