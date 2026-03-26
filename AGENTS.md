Be a minimalist when writing code. Prefer simplicity. The smaller the changeset, the fewer lines of total code, the easier it is to review a pull request. Use red/green TDD.

Use `okay-error` for fallible library code.

Library source under `packages/server/src` must never throw errors. Return `Result` / `Promise<Result>` values instead.
