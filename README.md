# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` lets an app connect external resources once and reuse fresh auth headers everywhere.

It stores encrypted credentials, runs OAuth, supports manual header-based auth, and resolves runtime headers from one stable connection path.

## Getting Started

Create the vault:

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

Ask `agent.pw` what to do next for a connection path and resource:

```ts
const prepared = await unwrap(
  agentPw.connect.prepare({
    path: "acme.connections.docs",
    resource: "https://docs.example.com/mcp",
  }),
);

if (prepared.kind === "ready") {
  return prepared.headers;
}

const option = prepared.options[0];
if (!option) {
  return null;
}

if (option.kind === "oauth") {
  const session = await unwrap(
    agentPw.connect.startOAuth({
      path: "acme.connections.docs",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
    }),
  );

  return Response.redirect(session.authorizationUrl, 302);
}

await unwrap(
  agentPw.connect.setHeaders({
    path: "acme.connections.docs",
    resource: "https://docs.example.com/mcp",
    headers: {
      Authorization: "Bearer api-key-value",
    },
  }),
);
```

Later, resolve fresh headers from the same path:

```ts
const headers = await unwrap(
  agentPw.connect.resolveHeaders({
    path: "acme.connections.docs",
  }),
);
```

`connect.prepare(...)` is the main decision point. It checks an exact-path credential first, then a matching profile, then discovery. If it returns `options`, the library's default recommendation is exposed as both `prepared.options[0]` and `prepared.resolution.option`.

## Why agent.pw

- One stable `path` per saved connection.
- OAuth and API keys collapse to one runtime interface: fresh headers.
- Profiles stay in the background as optional setup guidance.
- OAuth refresh stays inside the vault instead of leaking into app code.

## Docs

- [Getting Started](./docs/getting-started.md)
- [Reference](./docs/reference.md)
- [Credential Profiles](./docs/credential-profiles.md)
- [Architecture](./docs/architecture.md)
- [Security Model](./docs/security-model.md)
