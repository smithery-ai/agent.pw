# Security Model

`agent.pw` is an embeddable auth framework for applications that need to store credentials, guide connection setup, and resolve fresh runtime auth safely.

Its security model is built around five ideas:

- exact-path connections
- encrypted credential storage
- discovery-first OAuth with framework-owned refresh
- admin-configured profiles as setup guidance
- path-based authorization facts

This document describes what the framework enforces directly and what an implementer must provide around it.

## Framework Boundary

An implementer embeds `agent.pw` inside an application or service.

The implementer owns:

- user identity and sessions
- UI, routes, and interaction flows
- transport and request execution against upstream APIs
- deployment choices for SQL, `FlowStore`, and secret management
- application-specific metadata around a connection
- deriving rights from the application's own auth system

`agent.pw` owns:

- path validation and path-scoped lookups
- encrypted credential persistence
- guided auth selection through `connect.prepare(...)`
- OAuth lifecycle operations for stored credentials
- profile storage and profile matching
- rule evaluation and optional Biscuit helpers

That split keeps the framework focused on provider auth state and auth decisions while leaving product-specific control to the embedding app.

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

If two callers should not share credentials, they should not share a path.

## Credential Storage

Credentials are encrypted before being written to SQL.

The stored model is intentionally small:

- `path`
- `auth`
- encrypted `secret`
- timestamps

`secret.headers` is the runtime output for `oauth` and `headers` credentials. `env` credentials use `secret.env`.

OAuth credentials may also store encrypted lifecycle material such as:

- `accessToken`
- `refreshToken`
- `expiresAt`
- `scopes`
- endpoint metadata needed for refresh or revoke

Runtime callers typically consume headers, not raw secret payloads.

From an implementer perspective, the main obligations are:

- protect the encryption key separately from the database
- control who can read or use a connection path
- avoid copying decrypted headers or env values into logs or long-lived storage

## Resource as Setup Target

`resource` is the canonical setup target for `connect.*` flows.

This matters because:

- discovery-first OAuth starts from the protected resource
- manual and profile-guided setup still needs a stable target
- profile matching still needs a precise target

It does not need to be a top-level column on every stored credential. When a stored credential needs resource metadata later, `agent.pw` keeps it inside `auth` or encrypted OAuth state.

## Profiles

Profiles are configuration, not secrets.

They exist to help `agent.pw` guide setup when discovery is not enough.

Profiles can:

- define a manual header-entry template
- define an env-template for admin-facing vault setup
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

The framework's setup model is:

1. the app chooses a connection `path`
2. the app identifies the target `resource`
3. `connect.prepare(...)` checks for an existing credential
4. if none exists, the framework tries discovery-first OAuth
5. if discovery is unavailable or incomplete, the framework resolves matching profiles
6. the framework returns explicit next steps as `oauth` or `headers` options

This matters because implementers do not need to re-implement auth decision logic inconsistently across products or runtimes.

Generic env credentials live outside this guided setup flow and are written directly through `credentials.put(...)`.

## OAuth Lifecycle Ownership

For OAuth-backed credentials, `agent.pw` owns the provider lifecycle once the implementer calls into the framework:

- discover resource and authorization server metadata
- start authorization
- validate callback state
- exchange authorization codes
- refresh access tokens
- revoke on disconnect
- generate hosted callback and client metadata helpers when wanted

The implementation uses `oauth4webapi`, but the key security property is architectural: token lifecycle logic stays attached to the stored credential instead of being re-implemented ad hoc across the embedding app.

### Refresh-Aware Reads

`connect.headers({ path })` is refresh-aware by default for OAuth credentials.

Before returning headers, the framework can:

1. load the credential at the exact path
2. inspect expiry
3. refresh if needed
4. persist the new encrypted state
5. return fresh headers

This reduces the chance of apps leaking stale token handling into scattered call sites.

### Integrator-Controlled Routing

`agent.pw` does not require a specific daemon, proxy, or CLI.

The implementer decides:

- where OAuth routes live
- whether to use `createWebHandlers(...)` or wire routes manually
- how returned headers or env values are attached to downstream execution

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
- resolving env credentials for sandboxes or CLIs
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

`agent.pw/biscuit` is an optional token helper for the same rule model.

Apps that want Biscuit tokens can compile rules into Biscuits, attenuate them, and extract facts from them, but the framework does not depend on Biscuit for its own authorization semantics.

The core security model stays the same either way:

- paths define the protected namespace
- rules define the granted actions
- optional token formats can carry those facts across runtimes

## SQL Footprint

The framework-owned SQL footprint is intentionally small:

- `cred_profiles`
- `credentials`

Embedders can place those tables inside a custom SQL schema or prefix them to fit a shared database.

Apps own their own migration or DDL workflow for that footprint. That keeps the framework focused on provider auth configuration and encrypted credential state, while app-specific user, session, and audit tables remain in the embedding product.

## Implementer Checklist

When embedding `agent.pw`, verify these boundaries explicitly:

- choose stable connection paths and treat them as authorization boundaries
- store the encryption key separately from the credential database
- use a durable `FlowStore` in multi-instance deployments
- derive least-privilege rights before calling scoped APIs
- avoid logging decrypted headers, env values, tokens, or OAuth callback secrets
