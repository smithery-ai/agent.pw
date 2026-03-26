import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["./test/**/*.test.ts"],
    setupFiles: ["./test/vitest.setup.ts"],
    exclude: ["**/node_modules/**", "**/.context/**", "**/coverage/**", "**/dist/**", "**/.git/**"],
    coverage: {
      provider: "v8",
      all: true,
      include: ["packages/server/src/**/*.ts"],
      exclude: ["packages/server/src/db/schema/**", "packages/server/src/types.ts"],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
