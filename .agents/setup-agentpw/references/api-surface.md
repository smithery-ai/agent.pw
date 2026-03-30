# agent.pw API Surface

## Package exports

```ts
import { createAgentPw } from "agent.pw";                  // Core factory
import { createDb, createLocalDb, bootstrapLocalSchema } from "agent.pw/sql";
import { createInMemoryFlowStore } from "agent.pw/oauth";  // Dev-only flow store
import { can } from "agent.pw/rules";                      // Authorization checks
import * as paths from "agent.pw/paths";                    // Path utilities
import type { AgentPw, AgentPwOptions, ... } from "agent.pw/types";
import { isNotFoundError, isAuthorizationError, ... } from "agent.pw/errors";
```

## createAgentPw(options): Promise<Result<AgentPw>>

```ts
interface AgentPwOptions {
  db: Database;                    // From createDb or createLocalDb
  encryptionKey: string;           // 32 bytes, base64-encoded
  flowStore?: FlowStore;           // Required for OAuth flows
  sql?: SqlNamespaceOptions;       // { schema, tablePrefix }
  oauthClient?: OAuthClientConfig; // For hosted OAuth / dynamic registration
  oauthFetch?: typeof fetch;       // Custom fetch for OAuth requests
  clock?: () => Date;              // For testing
  logger?: Logger;                 // Custom logger
}
```

Returns `AgentPw` with four surfaces: `connect`, `credentials`, `profiles`, `scope()`.

## connect

### connect.prepare({ path, resource, response? }): Promise<Result<ConnectPrepareResult>>

Returns `{ kind: "ready", headers, credential, resolution }` or `{ kind: "options", options, resolution }`.

Each option has `kind: "oauth" | "headers"`.

### connect.startOAuth({ path, option, redirectUri, headers?, client? }): Promise<Result<AuthorizationSession>>

Returns `{ authorizationUrl, flowId }`. Redirect the user to `authorizationUrl`.

### connect.completeOAuth({ callbackUri }): Promise<Result<{ credential }>>

Call with the full callback URL including `code` and `state` params.

### connect.setHeaders({ path, resource, headers }): Promise<Result<void>>

Store header-based credentials (API keys, bearer tokens, etc).

### connect.resolveHeaders({ path, refresh? }): Promise<Result<Record<string, string>>>

Get fresh headers. Handles OAuth token refresh automatically. Pass `refresh: "force"` to force refresh.

### connect.disconnect({ path, revoke? }): Promise<Result<void>>

Delete credential. Pass `revoke: true` to also revoke OAuth tokens upstream.

### connect.classifyResponse({ resource, response }): Promise<Result<Challenge>>

Parse a 401/403 response. Returns `{ kind: "auth-required" | "step-up", scopes }`.

### connect.getFlow(flowId): Promise<Result<PendingFlow>>

Get pending OAuth flow state.

### connect.createWebHandlers({ callbackPath }): WebHandlers

Returns `{ start(request, opts), callback(request) }` for hosted OAuth.

### connect.createClientMetadataResponse(input): Response

Build a Client ID Metadata Document response.

## credentials

### credentials.get(path, { db? }): Promise<Result<CredentialRecord>>
### credentials.list({ path?, recursive?, db? }): Promise<Result<CredentialSummary[]>>
### credentials.put(input, { db? }): Promise<Result<void>>
### credentials.move(from, to, { db? }): Promise<Result<void>>
### credentials.delete(path, { db?, recursive? }): Promise<Result<void>>

## profiles

### profiles.get(path, { db? }): Promise<Result<CredentialProfileRecord>>
### profiles.list({ path?, recursive?, db? }): Promise<Result<CredentialProfileRecord[]>>
### profiles.put(path, data, { db? }): Promise<Result<void>>
### profiles.delete(path, { db?, recursive? }): Promise<Result<void>>
### profiles.resolve({ path, resource }): Promise<Result<CredentialProfileRecord | undefined>>

## scope(rules): ScopedAgentPw

```ts
const scoped = pw.scope({
  rights: [
    { action: "credential.use", root: "acme" },
    { action: "credential.manage", root: "acme.connections" },
  ],
});
```

Actions: `credential.use`, `credential.read`, `credential.manage`, `credential.connect`, `profile.read`.

Returns same API surface but all operations enforce path-based authorization.

## rules

```ts
import { can } from "agent.pw/rules";

can({
  rights: [{ action: "credential.use", root: "acme" }],
  action: "credential.use",
  path: "acme.connections.github",
}); // => true
```

## paths

- `validatePath(path)` — check ltree syntax
- `pathDepth(path)` — count segments
- `ancestorPaths(path)` — get hierarchy
- `isAncestorOrEqual(ancestor, descendant)`
- Pattern: `/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/`

## Database setup

### Development (PGlite)

```ts
const db = unwrap(await createLocalDb("./agentpw-data"));
unwrap(await bootstrapLocalSchema(db));
```

### Production (PostgreSQL)

```ts
const db = unwrap(createDb(process.env.DATABASE_URL!));
// You own migrations. Schema DDL is in packages/server/src/db/bootstrap-local.ts
```

### Namespacing

```ts
const sql = { schema: "platform", tablePrefix: "agentpw_" };
const db = unwrap(createDb(url, { sql }));
const pw = unwrap(await createAgentPw({ db, sql, ... }));
```

## FlowStore interface (for production OAuth)

```ts
interface FlowStore {
  create(flow: PendingFlow): Promise<void>;
  get(id: string): Promise<PendingFlow | null>;
  complete(id: string): Promise<void>;
  delete(id: string): Promise<void>;
}
```

`createInMemoryFlowStore()` is dev-only. Production multi-instance apps need a persistent implementation (Redis, database, etc).

## Error types

All functions return `Result<T>` from `okay-error`. Error types:

- `NotFound` — credential or profile doesn't exist
- `Authorization` — scope check failed
- `Conflict` — multiple profiles at same depth
- `Crypto` — encryption key issues (must be 32 bytes base64)
- `Input` — invalid path, bad arguments
- `OAuth` — OAuth flow errors
- `Expired` — token expired and refresh failed
- `Persistence` — database errors
- `Internal` — unexpected errors

Use type guards: `isNotFoundError(e)`, `isAuthorizationError(e)`, etc.
