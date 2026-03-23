# Security Model

`agent.pw` secures agent auth around four ideas:

- explicit binding roots
- encrypted credential storage
- refresh-aware OAuth runtime ownership
- portable path-based rules

This document focuses on those trust boundaries and enforcement mechanics. The full system structure is described in [architecture.md](./architecture.md).

## Trust Boundary

The host product owns:

- user identity and sessions
- UI and interaction flows
- runtime orchestration
- network transport and any external tokens it chooses to issue

`agent.pw` owns:

- path validation and tree-based resolution
- provider auth definitions
- encrypted credential storage
- OAuth token lifecycle for provider credentials
- rule evaluation over binding roots
- optional Biscuit compilation helpers

That split keeps the auth substrate inspectable and reusable without forcing a second server hop.

## Resource Security Model

### Credential Profiles

Profiles define how to authenticate to a provider at a path.

Examples:

```txt
/github
/acme/github
/acme/ws_eng/github
```

Profiles are configuration, not secrets. Their security properties are:

- path-local overrides stay explicit
- deeper definitions shadow broader definitions
- same-depth ambiguity is rejected

### Bindings

Bindings are the runtime root of trust for one connection or integration in a host product.

A binding declares:

- `root`
- `profilePath`

`profilePath` chooses the auth definition. `root` chooses the namespace subtree the connection can use for credential lookup and storage.

Runtime operations should execute against an explicit binding rather than against inferred request hosts or global user state. This matters for multi-tenant products because one user may operate across multiple roots during the same session.

An exact `credentialPath` may also be supplied by a caller, but that is an optional leaf override. It does not replace the role of the binding root as the namespace boundary.

### Credentials

Credentials store provider auth material encrypted at rest.

Security properties:

- secrets are encrypted before persistence
- runtime code resolves credentials through framework APIs instead of reading raw ciphertext directly
- refreshable OAuth material stays with the credential record that runtime resolution uses

### Rules

Rules are path grants:

```txt
right(root, action)
```

Examples:

```txt
credential.use on /acme
credential.manage on /acme/ws_eng
```

Rules are the framework’s canonical authorization facts. They can be enforced directly or compiled into another transport format later.

## Path Semantics

All policy is expressed over absolute slash-delimited paths.

Examples:

```txt
/acme
/acme/shared
/acme/ws_eng
/acme/ws_eng/user_alice
/acme/connections/github_primary
```

The framework does not store folder rows. Parent-child relationships are derived from path ancestry.

This gives the security model three properties:

- every resource has a stable namespace
- subtree scoping is uniform across profiles, credentials, and bindings
- authorization can be evaluated against roots rather than against ad hoc object ids

## Resolution Guarantees

### Profile Resolution

Given a binding root or candidate root:

1. find profiles whose path is applicable to that root
2. choose the deepest applicable match
3. fall back to a global default such as `/github`
4. reject same-depth conflicts

That makes organization-specific overrides explicit without flattening all provider knowledge into a single global row.

### Credential Resolution

Given an explicit binding:

1. find credentials under the binding root
2. keep only credentials tagged to the binding `profilePath`
3. choose the deepest applicable stored credential
4. reject same-depth conflicts

The framework stores `host` as metadata, but host is not the canonical runtime identity.

### Refresh-Aware Reads

Binding reads are refresh-aware when OAuth state is present.

Before returning headers, the framework can:

1. inspect the credential expiry
2. refresh through the configured provider flow when needed
3. persist the refreshed credential state
4. return fresh headers

This prevents host products from accidentally resolving stale provider tokens because the refresh logic stays attached to the vault itself.

## OAuth Lifecycle Ownership

The framework owns the provider OAuth runtime lifecycle.

That includes:

- generating PKCE authorization requests
- validating callback state
- exchanging authorization codes
- refreshing access tokens
- optionally revoking provider tokens on disconnect

The implementation uses `oauth4webapi`, but the important security property is architectural: embedded products do not need to re-implement provider token lifecycle logic outside the vault.

### Flow State

Pending OAuth flow state is stored behind `FlowStore`.

This is intentional:

- products can choose storage that matches their runtime model
- flow state can live in SQL, KV, or another shared ephemeral backend
- the framework does not silently assume single-process memory in production

An in-memory flow store exists only as an explicit helper for local development or tests.

### Hosted OAuth and Client Metadata

Embedded MCP clients often need two small hosted endpoints:

- an OAuth callback
- a client metadata document

The framework provides helpers to generate those responses without turning HTTP routing into the core abstraction. The hosted surface remains thin and declarative, while the auth lifecycle and storage stay inside the framework.

## Encrypted Storage

Credential secrets are encrypted with an application-provided encryption key before they are written to SQL.

The stored OAuth payload includes only the material needed for provider auth lifecycle:

- `accessToken`
- `refreshToken`
- `expiresAt`
- `scopes`
- `tokenType`

Runtime callers typically consume resolved headers, not the raw secret payload.

## Rule Enforcement

The framework can evaluate rules directly.

Examples:

- does `credential.use` on `/acme` cover `/acme/connections/github_primary`?
- which roots are visible for `credential.manage`?
- does a path constraint narrow a runtime request correctly?

This enforcement path lives in `agent.pw/rules` and does not require Biscuit or any other token system.

## Biscuit as an Optional Transport

`agent.pw/biscuit` compiles rules into Biscuit tokens for products that want capability-bearing tokens.

That module can:

- mint tokens from rule grants
- add attenuation constraints such as host, method, path, or TTL
- verify or inspect Biscuit payloads

The security model stays the same either way:

- roots define the resource scope
- rules define the granted actions
- optional token transports carry those facts to another runtime

## SQL Footprint

The current framework-owned SQL footprint is intentionally small:

- `cred_profiles`
- `credentials`

That keeps the vault focused on provider auth definitions and encrypted credential state. User auth, application sessions, and product-specific metadata remain in the embedding product.
