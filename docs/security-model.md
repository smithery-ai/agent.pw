# Security Model

`agent.pw` secures agent auth around five ideas:

- exact-path connections
- encrypted credential storage
- discovery-first OAuth with framework-owned refresh
- admin-configured profiles as setup guidance
- portable path-based rules

This document focuses on those trust boundaries and enforcement mechanics.

## Trust Boundary

The embedding app owns:

- user identity and sessions
- UI and interaction flows
- transport and request execution
- any external tokens it chooses to issue
- product-specific metadata around a connection

`agent.pw` owns:

- path validation
- encrypted credential storage
- OAuth runtime lifecycle
- guided auth selection through `connect.prepare(...)`
- profile storage and matching
- rule enforcement and optional Biscuit compilation

That split keeps auth state inspectable and reusable without forcing a second server hop.

## Connection Boundary

The core security boundary is the connection `path`.

Examples:

```txt
/acme/connections/github
/acme/connections/docs
/acme/workspaces/finance/connections/linear
```

Each exact path stores one credential.

Security implications:

- apps resolve auth by exact connection path
- multi-tenant products can scope access uniformly by path ancestry
- a path is stable enough to use for listing, grants, auditing, and runtime auth

## Credential Storage

Credentials are encrypted before being written to SQL.

The stored model is intentionally small:

- `path`
- `resource`
- `auth`
- encrypted `secret`
- timestamps

`secret.headers` is the canonical runtime output. OAuth credentials may also store encrypted lifecycle material such as:

- `accessToken`
- `refreshToken`
- `expiresAt`
- `scopes`
- endpoint metadata needed for refresh or revoke

Runtime callers typically consume headers, not raw secret payloads.

## Resource as Setup Target

`resource` is the canonical setup target for every credential, regardless of auth kind.

This matters because:

- discovery-first OAuth starts from the protected resource
- manual and profile-guided setup still needs a stable target
- the resource carries the full setup target for the connection

## Profiles

Profiles are configuration, not secrets.

They exist to help `agent.pw` guide setup when discovery is not enough.

Profiles can:

- define a manual header-entry template
- provide a fixed OAuth configuration
- override defaults within a path subtree
- constrain how an app should collect or shape credentials

They do not define the full space of allowed credentials. Apps can still store one-off manual credentials directly.

### Path-Scoped Configuration

Profiles live at paths and match connection paths by ancestry.

Examples:

```txt
/github
/acme/github
/acme/workspaces/finance/linear
```

Deeper matching profiles win when multiple profiles apply. That lets teams express defaults and more specific overrides without flattening configuration into a single global row.

## Guided Auth Flow

The security model for setup is:

1. the app chooses a connection `path`
2. the app identifies the target `resource`
3. `connect.prepare(...)` checks for an existing credential
4. if none exists, the framework tries discovery-first OAuth
5. if discovery is unavailable or incomplete, the framework resolves matching profiles
6. the framework returns explicit next steps as `oauth` or `headers` options

This matters because apps do not need to re-implement auth decision logic inconsistently across products or runtimes.

## OAuth Lifecycle Ownership

`agent.pw` owns the provider OAuth lifecycle:

- start authorization
- validate callback state
- exchange authorization codes
- refresh access tokens
- revoke on disconnect
- discover resource and authorization server metadata
- serve hosted callback and client metadata helpers when needed

The implementation uses `oauth4webapi`, but the key security property is architectural: token lifecycle logic stays attached to the vault instead of being split across apps.

### Refresh-Aware Reads

`connect.headers({ path })` is refresh-aware by default for OAuth credentials.

Before returning headers, the framework can:

1. load the credential at the exact path
2. inspect expiry
3. refresh if needed
4. persist the new encrypted state
5. return fresh headers

This reduces the chance of apps leaking stale token handling into ad hoc code paths.

## FlowStore

Pending OAuth flow state lives behind `FlowStore`.

This is an intentional security boundary:

- apps can choose storage that matches their deployment model
- multi-instance products can use shared KV or SQL
- local development can use explicit in-memory storage

The framework does not silently rely on process-local memory in production.

## Rules

Rules are path-based grants such as:

```txt
credential.use on /acme
credential.manage on /acme/connections
profile.read on /
```

Rules are the authorization facts that the framework understands directly.

That means the same grant language can protect:

- `connect.headers({ path })`
- `connect.prepare({ path, resource })`
- `credentials.get(path)`
- `credentials.list({ path })`
- `profiles.get(path)`
- `profiles.list({ path })`

## Scoped API

`agentPw.scope({ rights })` returns a scoped API that enforces rules automatically.

This gives embedders a consistent way to evaluate permissions before:

- using a credential
- connecting a resource
- listing credentials
- managing profiles

Example:

```ts
const api = agentPw.scope({
  rights: [{ action: 'credential.use', root: '/acme' }],
})

await api.connect.headers({ path: '/acme/connections/docs' })
```

The framework only asks for path-based rights because those are the facts it actually checks. Apps can derive those rights from Biscuits, sessions, or any other permission store.

## Biscuits

`agent.pw/biscuit` is an optional transport layer for the same rule model.

Apps that want Biscuit tokens can compile rules into Biscuits, but the framework does not depend on Biscuit for its own authorization semantics.

The core security model stays the same either way:

- paths define the protected namespace
- rules define the granted actions
- optional token formats carry those facts to another runtime

## SQL Footprint

The framework-owned SQL footprint is intentionally small:

- `cred_profiles`
- `credentials`

Embedders can place those tables inside a custom SQL schema or prefix them to fit a shared database.

That keeps the vault focused on provider auth configuration and encrypted credential state, while app-specific user/session tables remain in the embedding product.
