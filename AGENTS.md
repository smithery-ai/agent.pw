# Warden — Agent & Developer Conventions

## Database

- Use `pnpm run db:generate` to generate Drizzle migrations from schema changes. Never write migration SQL manually. Never run `db:migrate` — migrations are applied manually by the developer.

## HTTP Headers

- Avoid the `X-` prefix for custom headers — it is legacy and non-standard per RFC 6648. Use unprefixed names: `Warden-Signature`, `Warden-Callback`, `Warden-Event-Id`.

## Code Style

- See the global `CLAUDE.md` for TypeScript conventions (inferred return types, no dynamic imports, no re-exports).
