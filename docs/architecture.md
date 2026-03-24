# Architecture

This repo is the public source of truth for the `agent.pw` architecture.

## Summary

`agent.pw` is a credential vault and auth framework for agents.

The framework is built around one simple runtime model:

- a saved connection lives at an exact `path`
- that connection talks to a `resource`
- `agent.pw` stores one encrypted `credential` at that exact path
- `connect.prepare(...)` decides how that connection should authenticate
- `connect.headers(...)` returns fresh runtime headers for the same path

Profiles remain path-scoped configuration, but they are setup-time guidance and polyfills rather than the main runtime identity model.

## Concepts

### Path

A `path` is the durable identifier for one saved connection in an app.

Examples:

```txt
/acme/connections/github
/acme/connections/docs
/acme/workspaces/finance/connections/linear
```

The framework does not store folder rows. Hierarchy is implicit in the path itself.

### Resource

A `resource` is the protected resource that the connection talks to.

Examples:

```txt
https://api.github.com/
https://api.linear.app/
https://docs.example.com/mcp
```

`resource` is the canonical setup target for configuration, discovery, and stored credentials.

### Credential

A `credential` is the encrypted auth stored at one exact path.

Each credential stores:

- `path`
- `resource`
- `auth`
- encrypted `secret`
- timestamps

At runtime, `secret.headers` is the universal output shape. OAuth credentials may also include stored refresh state.

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
credential.use on /acme
credential.manage on /acme/connections
profile.read on /
```

The framework can enforce those rules directly or compile them into Biscuits.

## Public Package Boundary

The public package surface is:

```ts
import { createAgentPw } from 'agent.pw'
import * as oauth from 'agent.pw/oauth'
import * as rules from 'agent.pw/rules'
import * as biscuit from 'agent.pw/biscuit'
import * as sql from 'agent.pw/sql'
import * as paths from 'agent.pw/paths'
```

`createAgentPw(...)` returns:

- `connect`
- `credentials`
- `profiles`
- `authenticated(...)`

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

### `connect.start({ path, option, redirectUri, client? })`

Starts an OAuth flow from one returned OAuth option.

### `connect.complete({ callbackUri })`

Completes the OAuth flow, persists the credential at the exact path, and returns the stored credential.

### `connect.saveHeaders({ path, option, values })`

Stores a manual header-based credential at the exact path.

### `connect.headers({ path, refresh? })`

Returns runtime headers for the exact path.

When the stored credential is OAuth-backed, this call is refresh-aware by default.

### `connect.disconnect({ path, revoke? })`

Disconnects a stored credential and optionally revokes upstream OAuth tokens.

## Auth Kinds

At the framework level there are only two auth families:

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
3. try discovery-first OAuth for the `resource`
4. resolve path-scoped profiles that match the `resource`
5. build an ordered list of `oauth` and `headers` options
6. return those options

That gives the app a guided flow without forcing it to understand the framework’s internal selection logic.

## Discovery-First OAuth

When a resource publishes usable OAuth metadata, `agent.pw` uses it directly.

MCP servers are one example, but the model is broader than MCP.

The discovery-first flow is:

1. normalize the `resource`
2. discover protected-resource metadata
3. resolve the authorization server
4. start PKCE authorization
5. exchange the code on callback
6. store the resulting credential at the connection path

If discovery is unavailable or incomplete, the framework falls back to matching profiles.

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
- `resource`
- `auth`
- encrypted `secret`
- timestamps

That is enough because:

- the exact connection path is the runtime identity
- the resource is the setup target
- runtime consumption only needs resolved headers
- OAuth lifecycle state can live inside the encrypted secret payload

Profiles, discovery logic, and option selection happen around the credential. They are not the credential’s primary identity.

## Exact-Path Credentials

One exact path maps to one stored credential.

Examples:

```txt
/acme/connections/github
/acme/connections/resend
/acme/workspaces/finance/connections/linear
```

This keeps runtime resolution simple:

- `connect.headers({ path })`
- `credentials.get(path)`

Listing remains path-based:

- `credentials.list({ path })` returns direct children only under that path

## Authorization Surface

The framework exposes rules in two ways:

### Direct enforcement

Use `agent.pw/rules` with helpers like:

- `can(...)`
- `assertCan(...)`

### Scoped facade

Use `agentPw.authenticated(facts)` to get an API that enforces rules automatically for:

- `connect.*`
- `credentials.*`
- `profiles.*`

The callback form:

```ts
await agentPw.authenticated(facts, async api => {
  return api.connect.headers({ path: '/acme/connections/docs' })
})
```

is the ergonomic “operate within this authorization context” surface for embedders.

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
  schema: 'platform',
  tablePrefix: 'agentpw_',
}

const db = createDb(process.env.DATABASE_URL!, { sql })

const agentPw = await createAgentPw({
  db,
  sql,
  encryptionKey,
  flowStore,
})
```

The same namespace options should be passed to both the SQL helpers and `createAgentPw(...)`.

## Why This Shape

This design keeps the public model simple:

- apps think in `path` and `resource`
- `agent.pw` guides auth automatically
- profiles stay in the background as admin configuration
- credentials stay minimal and encrypted
- runtime consumers resolve fresh headers from exact paths

That gives embedders a stable auth substrate without forcing them into a particular UI, token format, or transport layer.
