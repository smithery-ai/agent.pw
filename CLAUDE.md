# agent.pw

OAuth credential management library for MCP servers. Used by Smithery's Connect, Gateway, and Auth workers.

## Commands

- `pnpm test` — run vitest with 100% coverage enforcement
- `pnpm run fmt` — format with oxfmt (not biome)
- `pnpm run fmt:check` — check formatting in CI

## Code Quality

- No type assertions (`as` forbidden by `consistent-type-assertions` lint rule). Use `instanceof`, `in`, and `typeof` narrowing.
- Use `okay-error` `Result` types (`ok()`, `err()`, `result()`) for fallible operations.
- Use named error constructors from `src/errors.ts` — never call `oauthError()` directly.
- Maintain 100% test coverage. Use `/* v8 ignore */` only for branches unreachable through mocked tests.

## Commits

- `type: short description` — 5 words or fewer
- Types: feat, fix, chore, refactor, docs, test
