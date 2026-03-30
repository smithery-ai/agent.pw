# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` is a credential vault for AI agents. It stores encrypted credentials, handles OAuth flows (PKCE, refresh, revocation, RFC 9728 discovery), and resolves fresh auth headers at runtime from one stable connection path.

```
npm install agent.pw
```

## Quick start

```ts
import { createAgentPw } from "agent.pw";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { createDb } from "agent.pw/sql";
import { unwrap } from "okay-error";

const db = unwrap(createDb(process.env.DATABASE_URL!));
const agentPw = await unwrap(
  createAgentPw({
    db,
    encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
    flowStore: createInMemoryFlowStore(),
  }),
);
```

### Connect to a resource

`connect.prepare` checks for an existing credential, then falls back to profiles or OAuth discovery:

```ts
const prepared = await unwrap(
  agentPw.connect.prepare({
    path: "acme.connections.docs",
    resource: "https://docs.example.com/mcp",
  }),
);

if (prepared.kind === "ready") {
  // Credential already exists — use the headers
  return prepared.headers;
}

// Take the first option (options are ordered by preference)
const option = prepared.options[0];

if (option?.kind === "oauth") {
  const session = await unwrap(
    agentPw.connect.startOAuth({
      path: "acme.connections.docs",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    }),
  );
  return Response.redirect(session.authorizationUrl, 302);
}

if (option?.kind === "headers") {
  // Collect headers from the user and store them
  await unwrap(
    agentPw.connect.setHeaders({
      path: "acme.connections.docs",
      resource: "https://docs.example.com/mcp",
      headers: { Authorization: "Bearer api-key-value" },
    }),
  );
}
```

### Resolve headers later

```ts
const headers = await unwrap(
  agentPw.connect.resolveHeaders({ path: "acme.connections.docs" }),
);
// OAuth tokens are refreshed automatically
```

## Features

- **Encrypted credential storage** — OAuth tokens and API keys stored at rest with AES-GCM
- **OAuth lifecycle** — PKCE, token refresh, revocation, RFC 9728 discovery
- **Credential profiles** — admin-configured templates for known providers or manual header entry
- **Path-based organization** — hierarchical `ltree` paths (`acme.connections.github`)
- **Scoped access** — enforce path-based rights via `agentPw.scope({ rights })`
- **Embeddable** — works with any Postgres-compatible database, no separate server required

## Docs

- [Getting started](./docs/getting-started.md) — setup, connect flow, OAuth callbacks
- [API reference](./docs/reference.md) — full `connect`, `credentials`, `profiles` API
- [Credential profiles](./docs/credential-profiles.md) — admin configuration for known providers
- [Architecture](./docs/architecture.md) — design decisions and data model
- [Security model](./docs/security-model.md) — path-based access, encryption, token scoping

## Development

```bash
pnpm install
pnpm build           # typecheck
pnpm test            # run tests (in-memory PGlite)
pnpm run lint        # lint
pnpm run db:generate # generate Drizzle migrations from schema changes
```

## License

[FSL-1.1-MIT](LICENSE.md) — converts to MIT after two years.
