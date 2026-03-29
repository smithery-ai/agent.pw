# Architecture

This repo is the public source of truth for the `agent.pw` architecture.

## Summary

`agent.pw` is a credential vault and auth framework for agents.

The framework is built around one simple runtime model:

- a saved connection lives at an exact `path`
- `agent.pw` stores one encrypted `credential` at that exact path
- `connect.prepare(...)` can use a `resource` to decide how that connection should authenticate
- `connect.resolveHeaders(...)` returns fresh runtime headers for the same path

Profiles remain path-scoped configuration, but they are setup-time guidance and polyfills rather than the main runtime identity model.

## Concepts

### Path

A `path` is the durable identifier for one saved connection in an app.

Paths use strict dot-separated `ltree` syntax. Each segment must match `[A-Za-z0-9_-]+`.

Examples:

```txt
acme.connections.github
acme.connections.docs
acme.workspaces.finance.connections.linear
```

The framework does not store folder rows. Hierarchy is implicit in the path itself.

### Resource

A `resource` is the protected resource a connect flow is trying to reach.

Examples:

```txt
https://api.github.com/
https://api.linear.app/
https://docs.example.com/mcp
```

`resource` is used for setup and discovery. It is not required for every stored credential.

### Credential

A `credential` is the encrypted auth stored at one exact path.

Each credential stores:

- `path`
- `auth`
- encrypted `secret`
- timestamps

At runtime:

- `oauth` and `headers` credentials expose `secret.headers`
- OAuth credentials may also include stored refresh state

### Profile

A `profile` is admin-configured setup guidance.

Profiles help `agent.pw` when it needs to:

- fall back from discovery to a known OAuth setup
- collect manual header-based credentials in a guided way
- override or constrain setup for specific paths
- support services that do not publish usable discovery metadata

Profiles are path-scoped so apps can express defaults and more specific org or workspace configuration.

They are not required for every connection, and they do not define the complete set of credentials the vault can hold.

### Rules

Rules are path grants such as:

```txt
credential.use on acme
credential.manage on acme.connections
profile.read (global)
```

The framework enforces those rules directly.

Global scope is represented by omitting `root`, not by using a root-path literal.

## Public Package Boundary

The public package surface is:

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

There is no built-in daemon, CLI, proxy surface, or required second server hop in this repo.

## Connect API

The `connect.*` API is the main product surface.

### `connect.prepare({ path, resource, response? })`

This is the entry point for guided auth.

It answers:

What should the app do next for this connection path and resource?

It returns:

- `ready`
  - a credential already exists at `path`
  - includes fresh headers and the current credential record
- `options`
  - includes a list of auth options the app can present
  - options are `oauth` or `headers`
  - an empty list means unconfigured

### `connect.startOAuth({ path, option, redirectUri, headers?, client? })`

Starts an OAuth flow from one returned OAuth option.

### `connect.completeOAuth({ callbackUri })`

Completes the OAuth flow, persists the credential at the exact path, and returns the stored credential.

### `connect.getFlow(flowId)`

Returns the current pending flow state for a known flow ID.

Missing flows return `NotFound`, not `null`. This is intentional: `getFlow` is a workflow continuation API, so absence is treated as an invalid or expired continuation step rather than a normal lookup miss.

### `connect.setHeaders({ path, headers, resource? })`

Stores app-supplied headers at the exact path.

This is the write path for both header-based auth and app-supplied non-auth connection headers.

When the stored credential is OAuth-backed, OAuth-owned auth headers remain authoritative and app-supplied non-auth headers are replaced.

### `connect.resolveHeaders({ path, refresh? })`

Returns runtime headers for the exact path.

When the stored credential is OAuth-backed, this call is refresh-aware by default.

### `connect.disconnect({ path, revoke? })`

Disconnects a stored credential and optionally revokes upstream OAuth tokens.

## Auth Kinds

At the vault level there are two credential families:

- `oauth`
- `headers`

Everything manual collapses into header auth:

- API keys
- bearer tokens
- basic auth
- custom vendor headers
- cookies

This keeps the stored model small while still covering the common real-world cases.

## Decision Flow

`connect.prepare(...)` follows one decision path:

1. check whether a credential already exists at `path`
2. if it does, return `ready`
3. resolve path-scoped profiles that match the `resource`
4. if a profile matches, use it as the authoritative route
5. otherwise try discovery for the `resource`
6. build `oauth` or `headers` options from the chosen route
7. return those options

Each `prepare(...)` result also includes `resolution`, so apps can inspect the canonical resource, selected source, and chosen option without a second API call.

## Profile-Aware OAuth

When a known profile matches, `agent.pw` uses that profile directly. Otherwise it falls back to resource discovery.

MCP servers are one example, but the model is broader than MCP.

The OAuth flow is:

1. normalize the `resource`
2. resolve the auth route from profile or discovery
3. start PKCE authorization
4. exchange the code on callback
5. store the resulting credential at the connection path

Flow state stays narrowly scoped to OAuth continuation data: path, resource, option, expiry, and PKCE state.

## Profiles as Admin Configuration

Profiles are intended for configuration phases, usually performed once by admins.

Two profile shapes matter:

### OAuth profile

Used when admins want a fixed OAuth setup or the resource does not publish enough discovery metadata.

Example fields:

- `issuer`
- `authorizationUrl`
- `tokenUrl`
- `revocationUrl`
- `clientId`
- `clientSecret`
- `clientAuthentication`
- `scopes`

### Header profile

Used to guide manual credential entry.

Header profiles define field metadata such as:

- `name`
- `label`
- `description`
- `prefix`
- `secret`

That lets the framework return a manual setup option without hard-coding the form in the app.

## Minimal Stored Model

The credential table intentionally stores very little:

- `path`
- `auth`
- encrypted `secret`
- timestamps

That is enough because:

- the exact connection path is the runtime identity
- the resource only matters when a connect flow or profile match needs it
- runtime consumption only needs resolved headers
- OAuth lifecycle state can live inside the encrypted secret payload

Profiles, discovery logic, and option selection happen around the credential. They are not the credential’s primary identity.

## Exact-Path Credentials

One exact path maps to one stored credential.

Examples:

```txt
acme.connections.github
acme.connections.resend
acme.workspaces.finance.connections.linear
```

This keeps runtime resolution simple:

- `connect.resolveHeaders({ path })`
- `credentials.get(path)`

Listing remains path-based:

- `credentials.list({ path })` returns direct children only under that path

Absence semantics differ by API category:

- lookup-style APIs such as `credentials.get(path)` may return `Ok(null)` when nothing is stored at that path
- workflow APIs such as `connect.getFlow(flowId)` return `Err(NotFound)` when the referenced state no longer exists

## Authorization Surface

The framework exposes rules in two ways:

### Direct enforcement

Use `agent.pw/rules` with helpers like:

- `can(...)`

### Scoped API

Use `agentPw.scope({ rights })` to get an API that enforces rules automatically for:

- `connect.*`
- `credentials.*`
- `profiles.*`

That scoped API can then be used directly:

```ts
const api = agentPw.scope({
  rights: [{ action: "credential.use", root: "acme" }],
});

await api.connect.resolveHeaders({ path: "acme.connections.docs" });
```

The framework only accepts the authorization facts it checks itself: path-based rights. Apps can derive those rights from sessions or any other permission store.

## OAuth Runtime Ownership

`agent.pw` owns the provider OAuth lifecycle.

That includes:

- authorization start
- callback completion
- token refresh
- token revocation on disconnect
- discovery-first resource handling
- hosted callback helpers
- client metadata document helpers for CIMD-style clients

The implementation uses `oauth4webapi`, but the important architectural point is that apps do not need to re-implement provider token lifecycle logic outside the vault.

## Flow Storage

OAuth handoff state is stored behind a `FlowStore` interface.

That allows embedders to choose storage that matches their runtime:

- SQL
- KV
- Redis
- in-memory storage for local development

The framework does not assume process-local memory in production.

## Hosted OAuth and Client Metadata

Apps that need to host a callback or serve a Client ID Metadata Document can use:

- `connect.createWebHandlers(...)`
- `connect.createClientMetadataDocument(...)`
- `connect.createClientMetadataResponse(...)`

These helpers are optional. They do not turn HTTP routing into the core abstraction.

## SQL Namespace Configuration

Embedders can place framework tables in a custom schema or prefix them:

```ts
const sql = {
  schema: "platform",
  tablePrefix: "agentpw_",
};

const db = createDb(process.env.DATABASE_URL!, { sql });

const agentPw = await createAgentPw({
  db,
  sql,
  encryptionKey,
  flowStore,
});
```

The same namespace options should be passed to both the SQL helpers and `createAgentPw(...)`.

Apps own their own migration or DDL workflow. The framework exposes schema and query helpers, but it does not ship migrations as part of the package contract.

## Why This Shape

This design keeps the public model simple:

- apps think in `path` and `resource`
- `agent.pw` guides auth automatically
- profiles stay in the background as admin configuration
- credentials stay minimal and encrypted
- runtime consumers resolve fresh headers from exact paths

That gives embedders a stable auth substrate without forcing them into a particular UI, token format, or transport layer.
