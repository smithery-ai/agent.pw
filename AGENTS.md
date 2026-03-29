Be a minimalist when writing code. Prefer simplicity. The smaller the changeset, the fewer lines of total code, the easier it is to review a pull request. Use red/green TDD.

Avoid unnecessary `instanceof` checks and overly defensive code paths. Write the tightest accurate types possible, and validate at boundaries so downstream code can rely on those types without extra guarding.

Use `okay-error` for fallible library code.

Library source under `packages/server/src` must never throw errors. Return `Result` / `Promise<Result>` values instead.
