# agent.pw

[![npm version](https://img.shields.io/npm/v/agent.pw)](https://www.npmjs.com/package/agent.pw)

`agent.pw` helps apps connect external resources once and reuse the resulting auth safely across agents, tools, MCP clients, and sandboxed CLIs.

It stores encrypted credentials, runs OAuth flows, supports manual header-based auth, and resolves fresh authenticated headers from a connection `path`.

## Concepts

- `path`: one saved connection in your app, such as `acme.connections.github`
- `resource`: the protected resource a connect flow is trying to access, such as `https://api.github.com/` or `https://docs.example.com/mcp`
- `credential`: the encrypted auth stored at that exact path
- `profile`: admin-configured setup guidance and polyfills that help `agent.pw` choose the right auth path
- `rules`: path-based authorization facts that can be enforced directly

Profiles are background configuration. End users usually do not need to know they exist.

Paths use strict dot-separated `ltree` syntax. Each segment must match `[A-Za-z0-9_-]+`.

## Package Surface

```ts
import { createAgentPw } from "agent.pw";
import * as oauth from "agent.pw/oauth";
import * as rules from "agent.pw/rules";
import * as sql from "agent.pw/sql";
import * as paths from "agent.pw/paths";
```

`createAgentPw(...)` returns:

- `connect`
- `credentials`
- `profiles`
- `scope(...)`

## Quick Start

```ts
import { createAgentPw } from "agent.pw";
import { createDb } from "agent.pw/sql";
import { createInMemoryFlowStore } from "agent.pw/oauth";
import { unwrap } from "okay-error";

const sql = {
  schema: "agentpw",
  tablePrefix: "",
};

const db = unwrap(createDb(process.env.DATABASE_URL!, { sql }));
const agentPw = await unwrap(
  createAgentPw({
    db,
    sql,
    encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
    flowStore: createInMemoryFlowStore(),
  }),
);
```

`createInMemoryFlowStore()` is a development helper. Multi-instance apps should pass a shared or persistent `FlowStore`.

## Guided Connect Flow

The main API is `connect.*`, with `prepare(...)` as the choice-bearing entry point.

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

const [option] = prepared.options;
if (!option) {
  console.error("This resource is not configured yet");
  return;
}

if (option.kind === "oauth") {
  const session = await unwrap(
    agentPw.connect.startOAuth({
      path: "acme.connections.docs",
      option,
      redirectUri: "https://app.example.com/oauth/callback",
      headers: {
        "X-Workspace": "acme",
      },
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

Later, resolve fresh headers for that same connection:

```ts
const headers = await unwrap(
  agentPw.connect.resolveHeaders({
    path: "acme.connections.docs",
  }),
);
```

## `connect.prepare(...)`

`connect.prepare(...)` always answers one question:

What should this app do next for this connection path and resource?

It returns one of:

- `ready`: a credential already exists at `path`
- `options`: a list of possible auth routes

Each returned option is self-contained. Apps pass the chosen option into either:

- `connect.startOAuth(...)` for OAuth
- `connect.setHeaders(...)` for header-based auth after building final headers from the option metadata

An empty `options` list means the resource is currently unconfigured.

Each `prepare(...)` result includes `resolution`, which exposes the library decision as structured metadata:

- `canonicalResource`
- `source`: `profile`, `discovery`, or `null`
- `reason`: why that route won
- `profilePath`
- `option`

## Auth Kinds

At the vault level there are two credential kinds:

- `oauth`
- `headers`

API keys are header auth. Basic auth, bearer tokens, vendor-specific headers, cookies, and similar schemes are all header auth.

Credentials always store the runtime material they need:

- `oauth` and `headers` credentials store resolved runtime headers
- OAuth credentials may also store refresh state so `agent.pw` can keep headers fresh

## Profile-Aware OAuth

When a known profile matches, `agent.pw` prefers that profile and skips generic discovery. Otherwise it falls back to resource discovery. MCP servers are one example, but the flow is not MCP-specific.

For the full matching rules, override behavior, and embedder guidance, see [docs/credential-profiles.md](./docs/credential-profiles.md).

```ts
const prepared = await unwrap(
  agentPw.connect.prepare({
    path: "acme.connections.docs",
    resource: "https://docs.example.com/mcp",
    response: unauthorizedResponse,
  }),
);
if (prepared.kind !== "options") {
  console.error("Resource is already connected");
  return;
}

console.log(prepared.resolution);
// {
//   canonicalResource: 'https://docs.example.com/mcp',
//   source: 'profile',
//   reason: 'matched-profile',
//   profilePath: 'docs',
//   option: { kind: 'oauth', ... }
// }
```

When the callback returns:

```ts
const completed = await unwrap(
  agentPw.connect.completeOAuth({
    callbackUri: "https://app.example.com/oauth/callback?code=...&state=...",
  }),
);

console.log(completed.credential);
```

Pending OAuth state is readable through the same API surface:

```ts
const flow = await unwrap(agentPw.connect.getFlow(flowId));
```

The helper keeps examples focused on the happy path. Production code should usually handle `Err` results explicitly instead of throwing.

`connect.resolveHeaders(...)` is refresh-aware by default, so apps do not need to re-implement token refresh outside the vault.

## Profiles

Profiles are admin-side configuration for advanced setup control.

Use them when an embedder wants to:

- override discovery for a known resource
- work around broken or incomplete upstream metadata
- define header-entry templates for admin UIs
- apply global defaults and narrower org or workspace overrides

The full matching model and examples live in [docs/credential-profiles.md](./docs/credential-profiles.md).

One important rule: profiles are only consulted for fresh guided setup. If an exact-path credential already exists, `connect.prepare(...)` returns that credential instead of re-resolving profiles.

```ts
await agentPw.profiles.put("resend", {
  resourcePatterns: ["https://api.resend.com*"],
  displayName: "Resend",
  auth: {
    kind: "headers",
    label: "Resend API key",
    fields: [
      {
        name: "Authorization",
        label: "API key",
        description: "Your Resend API key",
        prefix: "Bearer ",
        secret: true,
      },
    ],
  },
});
```

OAuth profiles define the auth configuration the framework should use when discovery is not enough or an admin wants a fixed setup:

```ts
await agentPw.profiles.put("linear", {
  resourcePatterns: ["https://api.linear.app/*"],
  displayName: "Linear",
  auth: {
    kind: "oauth",
    authorizationUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    clientId: process.env.LINEAR_CLIENT_ID!,
    clientSecret: process.env.LINEAR_CLIENT_SECRET!,
    scopes: "read write",
  },
});
```

Profiles are path-scoped configuration, so apps can keep global defaults and more specific org or workspace overrides.

## One-Off Credentials

Profiles guide setup, but they do not define what is possible.

Apps can still store a one-off credential directly:

```ts
await agentPw.credentials.put({
  path: "acme.connections.manual_resend",
  auth: {
    kind: "headers",
    label: "Manual Resend key",
    resource: "https://api.resend.com/",
  },
  secret: {
    headers: {
      Authorization: "Bearer rs_live_123",
    },
  },
});
```

List stored credentials:

```ts
const all = await agentPw.credentials.list();
const children = await agentPw.credentials.list({ path: "acme.connections" });
const subtree = await agentPw.credentials.list({ path: "acme", recursive: true });
```

Without `path`, returns everything. With `path`, returns direct children. With `recursive: true`, returns all descendants (backed by a GiST index on the ltree column).

## CRUD Options

Every `credentials.*` and `profiles.*` method accepts an optional `{ db }` to run the operation on a Drizzle transaction instead of the default connection. `list` and `delete` also accept `{ recursive }` to operate on the full subtree.

```ts
import type { Database } from "agent.pw";

await db.transaction(async (tx: Database) => {
  await tx.delete(orgs).where(eq(orgs.id, orgId));
  await agentPw.credentials.delete(orgId, { db: tx, recursive: true });
  await agentPw.profiles.delete(orgId, { db: tx, recursive: true });
});
```

## Scoped API

Use `scope(...)` to get a scoped API that enforces rules automatically.

```ts
const api = agentPw.scope({
  rights: [{ action: "credential.use", root: "acme" }],
});

const headers = await api.connect.resolveHeaders({
  path: "acme.connections.docs",
});
```

Apps are responsible for deriving those rights from whatever auth system they use, such as a session or an internal permission store.

`scope(...)` only accepts the facts the framework actually checks: path-based rights.

## Rules

Rules are the base authorization model.

```ts
import { can } from "agent.pw/rules";

const allowed = can({
  rights: [{ action: "credential.use", root: "acme" }],
  action: "credential.use",
  path: "acme.connections.docs",
});
if (!allowed) {
  throw new Error("Missing credential.use for acme.connections.docs");
}
```

## Hosted OAuth and Client Metadata

Apps that need a hosted OAuth callback and a Client ID Metadata Document can use the built-in helpers:

```ts
const handlers = agentPw.connect.createWebHandlers({
  callbackPath: "/oauth/callback",
});

export async function oauthStart(request: Request) {
  return handlers.start(request, {
    path: "acme.connections.docs",
    option: {
      kind: "oauth",
      source: "discovery",
      label: "Docs",
      resource: "https://docs.example.com/mcp",
    },
  });
}

export async function oauthCallback(request: Request) {
  return handlers.callback(request);
}

export async function clientMetadata() {
  return agentPw.connect.createClientMetadataResponse({
    clientId: "https://app.example.com/.well-known/oauth-client",
    redirectUris: ["https://app.example.com/oauth/callback"],
    clientName: "App Client",
    tokenEndpointAuthMethod: "none",
  });
}
```

Under the hood, OAuth is implemented with [`oauth4webapi`](https://github.com/panva/oauth4webapi).

## SQL Namespace Configuration

Embedders can place `agent.pw` tables in a custom schema or prefix them:

```ts
const sql = {
  schema: "platform",
  tablePrefix: "agentpw_",
};

const db = createDb(process.env.DATABASE_URL!, { sql });

const agentPw = await createAgentPw({
  db,
  sql,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  flowStore,
});
```

The same `sql` options should be passed to both the database helpers and `createAgentPw(...)`.

Apps own their own SQL migrations or DDL. `agent.pw` exports schema and query helpers, but it does not ship framework-owned migration files.

## More Docs

- [Architecture](./docs/architecture.md)
- [Security Model](./docs/security-model.md)
