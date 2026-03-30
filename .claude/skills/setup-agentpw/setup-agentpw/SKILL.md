---
name: setup-agentpw
description: Set up agent.pw credential management in agent applications. Use when adding credential storage, OAuth flows, API key management, or auth header resolution to an agent platform. Triggers on "set up agent.pw", "add agent.pw", "integrate agent.pw", "credential management", "store credentials", "OAuth for agents", "connect external APIs", or when building agent apps that need to call authenticated external APIs on behalf of users.
---

# Integrate agent.pw

agent.pw is a credential vault for agent platforms — 1Password for AI agents. Store OAuth tokens and API keys encrypted, resolve fresh auth headers from any agent or tool.

## Setup (every integration needs this)

```ts
import { createAgentPw } from "agent.pw";
import { createLocalDb, bootstrapLocalSchema } from "agent.pw/sql";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { unwrap } from "okay-error";

// Dev: PGlite (no external DB)
const db = unwrap(await createLocalDb("./agentpw-data"));
unwrap(await bootstrapLocalSchema(db));

// Production: PostgreSQL
// const db = unwrap(createDb(process.env.DATABASE_URL!));

const pw = unwrap(
  await createAgentPw({
    db,
    encryptionKey: process.env.AGENTPW_KEY!, // 32 bytes, base64
    flowStore: createInMemoryFlowStore(),     // Dev only — use persistent store in prod
  }),
);
```

Generate an encryption key: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`

## Core flow

```
pw.connect.setHeaders(...)     → store API key / bearer token
pw.connect.resolveHeaders(...) → get fresh headers (auto-refreshes OAuth)
pw.connect.prepare(...)        → "what should the app do next?" → ready | options
pw.connect.startOAuth(...)     → begin OAuth flow → redirect user
pw.connect.completeOAuth(...)  → handle callback → credential stored
pw.scope(rights)               → enforce tenant isolation
```

## Gotchas

- **bootstrapLocalSchema is required.** `createLocalDb` creates the PGlite instance but NOT the tables. Always call `bootstrapLocalSchema(db)` after.
- **Encryption key must be exactly 32 bytes, base64-encoded.** Anything else gives a `Crypto` error.
- **All functions return `Result<T>` from okay-error.** Use `unwrap()` for quick prototyping, `result.ok` / `result.value` / `result.error` in production.
- **`createInMemoryFlowStore()` is dev-only.** Multi-instance production apps need a persistent `FlowStore` (Redis, DB, etc).
- **Ships TypeScript source.** Consumers need `tsx` or a build step — raw Node.js won't work.
- **Paths are ltree syntax.** Dot-separated, each segment `[A-Za-z0-9_-]+`. Example: `acme.connections.github`.
- **Profiles are only consulted for fresh setup.** If a credential already exists at the path, `prepare()` returns `ready` and skips profile resolution.

## References

- **Full API surface**: See [references/api-surface.md](references/api-surface.md) for all methods, types, and options.
- **Integration patterns**: See [references/patterns.md](references/patterns.md) for header auth, OAuth flows, multi-tenant scoping, proxy pattern, hosted OAuth, transactions, and admin UI profiles.
- **Credential profiles**: See `docs/credential-profiles.md` in the repo for profile matching rules and override behavior.
- **Security model**: See `docs/security-model.md` in the repo for encryption and trust boundaries.
- **Source**: Library source is in `packages/server/src/`. Entry point is `index.ts`, database setup in `db/`, OAuth in `oauth.ts`.
