# Reference

This document covers the detailed `agent.pw` package surface beyond the quick start.

## Package Surface

```ts
import { createAgentPw } from "agent.pw";
import * as oauth from "agent.pw/oauth";
import * as identity from "agent.pw/identity";
import * as rules from "agent.pw/rules";
import * as sql from "agent.pw/sql";
import * as paths from "agent.pw/paths";
```

`createAgentPw(...)` returns:

- `connect`
- `credentials`
- `profiles`
- `scope(...)`

## Auth Kinds

At the vault level there are two credential kinds:

- `oauth`
- `headers`

API keys, bearer tokens, basic auth, custom vendor headers, and cookies all collapse into header auth.

Credentials always store the runtime material they need:

- `oauth` and `headers` credentials store resolved runtime headers
- OAuth credentials may also store refresh state so `agent.pw` can keep headers fresh

## `connect.*`

### `connect.prepare({ path, resource, response? })`

This is the entry point for guided connection setup.

It returns one of:

- `ready`
- `input_required`
- `options`

`input_required` means a matching profile requires HTTP inputs before the flow can continue.

The payload includes:

- `input.http.headers`
- `input.http.query`
- `input.missing.headers`
- `input.missing.query`

The important model split is:

- query params stay in the `resource` URL
- headers are stored through `connect.setHeaders(...)`
- `options` only contains OAuth routes

After the app updates the URL query params and/or stores headers, it should call `connect.prepare(...)` again.

### `connect.classifyResponse({ response, resource? })`

Use this when you are handling an upstream response directly and only need to know whether it is a Bearer auth challenge.

It returns:

- `none`
- `auth-required`
- `step-up`

Use `connect.prepare({ path, resource, response })` instead when you want `agent.pw` to convert that response into the next auth option for a concrete connection path.

### `connect.startOAuth({ path, option, redirectUri, headers?, client? })`

Starts OAuth from one returned OAuth option.

### `connect.completeOAuth({ callbackUri })`

Completes the callback, persists the credential at the exact path, and returns the stored credential.

### `connect.getFlow(flowId)`

Returns the current pending flow state for a known flow ID.

Missing flows return `NotFound`, not `null`. This is intentional because `getFlow` is a workflow continuation API, not a lookup-style API.

### `connect.setHeaders({ path, headers, resource? })`

Stores app-supplied headers at the exact path.

This is the write path for both:

- header-based auth
- app-supplied non-auth connection headers

This method only stores headers. Query params remain in the `resource` URL and are never stored by `agent.pw`.

When a matched profile defines `http.headers`, submitted headers must be a subset of those declared header names.

When the stored credential is OAuth-backed, OAuth-owned auth headers remain authoritative and app-supplied non-auth headers are replaced.

### `connect.resolveHeaders({ path, refresh? })`

Returns runtime headers for the exact path.

When the stored credential is OAuth-backed, this call is refresh-aware by default.

### ID-JAG Challenge Resolution

Configure `identityGrant` when the app can issue ID-JAG assertions for a user principal:

```ts
import { createAgentPw } from "agent.pw";
import { pairwiseIdentitySubject } from "agent.pw/identity";
import { unwrap } from "okay-error";

const agentPw = await unwrap(
  createAgentPw({
    db,
    encryptionKey,
    oauthClient: { clientId: "agentpw-client" },
    identityGrant: {
      issuer: "https://idp.example.com",
      clientId: "agentpw-client",
      signingKey: { privateJwk },
      subject: pairwiseIdentitySubject({ secret: subjectSecret }),
    },
  }),
);
```

Publish `agentPw.connect.createIdentityJwksResponse()` at the JWKS URI for the configured issuer.

For a resource challenge, call `connect.resolveChallengeHeaders({ path, resource, response, principal })`. OAuth refresh is tried first on `401`; if the retried request still returns an auth challenge, call the helper again with the new response to reach ID-JAG exchange. Use `refreshOAuth: false` when the caller already knows OAuth refresh should be skipped.

`connect.exchangeIdentityGrant({ path, resource, response, principal })` runs only the ID-JAG exchange. The `path` is required because scoped APIs enforce `credential.use` against it.

### `connect.disconnect({ path, revoke? })`

Disconnects a stored credential and optionally revokes upstream OAuth tokens.

## One-Off Credentials

Profiles guide setup, but they do not define what is possible.

Apps can still store a credential directly:

```ts
await agentPw.credentials.put({
  path: "acme.connections.manual_resend",
  resource: "https://api.resend.com/",
  auth: {
    kind: "headers",
  },
  secret: {
    headers: {
      Authorization: "Bearer rs_live_123",
    },
  },
});
```

## `credentials.*`

### `credentials.get(path)`

Returns the stored credential at an exact path, or `null` when none exists.

### `credentials.list({ path?, recursive? })`

Examples:

```ts
const all = await agentPw.credentials.list();
const children = await agentPw.credentials.list({ path: "acme.connections" });
const subtree = await agentPw.credentials.list({ path: "acme", recursive: true });
```

Without `path`, this returns everything. With `path`, it returns direct children. With `recursive: true`, it returns all descendants.

### `credentials.put(input)`

Writes a credential directly.

### `credentials.move(fromPath, toPath)`

Moves a credential between exact paths.

### `credentials.delete(path, { recursive? })`

Deletes one credential or a subtree.

## `profiles.*`

Profiles are admin-side configuration for advanced setup control.

Use them when an embedder wants to:

- override discovery for a known resource
- work around broken or incomplete upstream metadata
- define literal HTTP input templates for admin UIs
- apply global defaults and narrower org or workspace overrides

For matching rules and examples, see [Credential Profiles](./credential-profiles.md).

## CRUD Options

Every `credentials.*` and `profiles.*` method accepts an optional `{ db }` to run the operation on a Drizzle transaction instead of the default connection. `list` and `delete` also accept `{ recursive }` to operate on the full subtree.

```ts
import type { Database } from "agent.pw";

await db.transaction(async (tx: Database) => {
  await agentPw.credentials.delete("acme", { db: tx, recursive: true });
  await agentPw.profiles.delete("acme", { db: tx, recursive: true });
});
```

## Scoped API

Use `scope(...)` to get an API that enforces rules automatically.

```ts
const api = agentPw.scope({
  rights: [{ action: "credential.use", root: "acme" }],
});

const headers = await api.connect.resolveHeaders({
  path: "acme.connections.docs",
});
```

Apps are responsible for deriving those rights from their own auth system.

## Rules

Rules are the base authorization model.

```ts
import { can } from "agent.pw/rules";

const allowed = can({
  rights: [{ action: "credential.use", root: "acme" }],
  action: "credential.use",
  path: "acme.connections.docs",
});
```

## Hosted OAuth and Client Metadata

Apps that need a hosted OAuth callback and a Client ID Metadata Document can use the built-in helpers:

```ts
const agentPw = await createAgentPw({
  db,
  encryptionKey: process.env.AGENTPW_ENCRYPTION_KEY!,
  flowStore,
  oauthClient: {
    metadata: {
      clientId: "https://app.example.com/.well-known/oauth-client",
      redirectUris: ["https://app.example.com/oauth/callback"],
      clientName: "App Client",
      tokenEndpointAuthMethod: "none",
    },
    useDynamicRegistration: true,
  },
});

const handlers = agentPw.connect.createWebHandlers({
  callbackPath: "/oauth/callback",
});

const clientMetadataResponse = agentPw.connect.createClientMetadataResponse({
  clientId: "https://app.example.com/.well-known/oauth-client",
  redirectUris: ["https://app.example.com/oauth/callback"],
  clientName: "App Client",
  tokenEndpointAuthMethod: "none",
});
```

Use `oauthClient.clientId` when the app already has a fixed registered client ID.

Use `oauthClient.metadata.clientId` when the client ID is the URL of a hosted Client ID Metadata Document. In that case, the same URL should be served by `connect.createClientMetadataResponse(...)`.

Set `useDynamicRegistration: true` when the authorization server may require dynamic client registration from that metadata instead of accepting the metadata document URL directly.

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

The same `sql` options should be passed to both the SQL helpers and `createAgentPw(...)`.
