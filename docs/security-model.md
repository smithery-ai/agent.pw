# Security Model

`agent.pw` is built around four primitives:

- path-scoped `Credential Profiles`
- explicit `Bindings`
- encrypted `Credentials`
- scoped Biscuit-based `Agent Access`

The framework does not own an HTTP surface. A host product embeds these primitives directly and decides how agents, users, and runtimes interact with them.

The public architecture for how those primitives fit together lives in [architecture.md](./architecture.md). This document focuses on the security contract.

## Resource Model

### Credential Profile

A `Credential Profile` is the auth definition for a provider at a path.

Examples:

```txt
/github
/org_acme/github
/org_acme/ws_eng/github
```

Profiles define things like:

- provider hosts
- supported auth schemes
- provider-specific OAuth configuration

Profiles are tree-scoped. A deeper profile overrides a broader one when both apply.

### Credential

A `Credential` is the encrypted auth material stored at a path.

Examples:

```txt
/org_acme/github
/org_acme/ws_eng/linear
/org_acme/ws_eng/user_alice/notion
```

The stored payload is write-only from the framework’s perspective:

- credentials are encrypted before they are persisted
- normal runtime access goes through framework APIs
- agents consume scoped access and resolved credentials without seeing raw secret storage

### Binding

A `Binding` is the explicit runtime association between a host product resource and agent.pw auth state.

A Binding declares:

- `root`: the subtree where credentials for that resource live
- `profilePath`: the Credential Profile the resource uses

This is the primary embedded contract of the framework. Products resolve runtime auth from a Binding, not from inferred request hosts.

### Agent Access

`Agent Access` is a Biscuit token plus optional tracked metadata in `issued_tokens`.

Tokens carry:

- identity facts such as `user_id(...)`, `org_id(...)`, `home_path(...)`, and `scope(...)`
- explicit `right(root, action)` grants
- optional attenuation constraints over host, method, path, root, and TTL

## Paths

All policy is expressed against absolute slash-delimited paths.

Examples:

```txt
/org_acme
/org_acme/shared
/org_acme/ws_eng
/org_acme/ws_eng/user_alice
```

The framework does not store folder rows. Hierarchy is implicit in path segments.

## Rights Model

The framework treats `right(root, action)` as the canonical capability fact.

Examples:

```datalog
user_id("usr_123");
org_id("org_acme");
right("/org_acme", "credential.use");
right("/org_acme", "credential.manage");
right("/org_acme/connections/github_prod", "token.mint");
scope("repo");
```

`home_path(...)` is optional convenience metadata. It can be useful to a host product, but runtime authorization should not depend on a singular home path being present.

## Resolution

### Binding Resolution

Runtime resolution is Binding-first:

1. The host product identifies a Binding.
2. The Binding supplies `root` and `profilePath`.
3. agent.pw resolves stored auth from that Binding.
4. Optional adapters may infer a Binding from request shape, but they are not the core contract.

This matters for multi-tenant products. One user may have access to more than one root, so the active runtime root should be explicit and binding-scoped.

### Profile Resolution

Given a Binding or candidate root, profiles resolve by applicability:

1. Find profiles whose parent path is an ancestor of the requested root.
2. Prefer the deepest applicable path.
3. Fall back to root-level defaults such as `/github` or `/linear`.
4. Same-depth ambiguity is an error.

This makes path-local overrides explicit without flattening provider knowledge into one global table.

### Credential Resolution

Credentials resolve the same way:

1. Start from the Binding’s `root` and `profilePath`.
2. Keep credentials inside the Binding root that belong to the Binding’s `profilePath`.
3. Choose the deepest applicable credential.
4. Same-depth ambiguity is an error.

This lets a product keep credentials portable while still narrowing them by org, workspace, or user subtree, without making runtime auth depend on host inference.

## Biscuit Tokens

Tokens use an `apw_` transport prefix over a base64-encoded Biscuit.

Authority facts look like:

```datalog
user_id("usr_123");
org_id("org_acme");
home_path("/org_acme");
right("/org_acme", "credential.use");
right("/org_acme", "credential.manage");
scope("repo");
```

Attenuation can add checks such as:

```datalog
check if host($host), ["api.linear.app"].contains($host);
check if operation($op), ["GET"].contains($op);
check if path($path), $path.starts_with("/org_acme");
check if requested_root($root), ["/org_acme"].contains($root);
```

## Authorization Pipeline

Authorization is evaluated in two layers:

1. framework path-right checks confirm that the token carries `right(root, action)` covering the requested path
2. Biscuit attenuation checks are evaluated against ambient facts such as action, host, method, path, and requested root

That split is intentional. The path model stays explicit in framework code, while Biscuit carries monotonic attenuation rules that child tokens can only narrow.

The framework enforces four things during authorization:

- the token parses and validates
- the token still validates and has not been revoked
- the token’s explicit rights cover the requested path/action
- any attenuation checks on host, method, path, root, service, or TTL still pass

Ambient facts supplied to the authorizer include:

```datalog
resource("api.linear.app");
operation("GET");
path("/org_acme/tasks/123");
action("credential.use");
host("api.linear.app");
requested_root("/org_acme");
time(2026-03-23T15:00:00.000Z);
```

The framework also supports multiple rights on one token. List operations can union visible roots, while runtime operations should still execute against one explicit Binding root.

Tracked tokens are recorded in `issued_tokens`, so host products can inspect usage and revoke by logical token ID instead of only by bearer string.

## Revocation

Each Biscuit block has a revocation identifier.

`agent.pw` stores revoked block ids in `revocations`. A tracked token revocation also writes the tracked token’s block ids into the revocation table, which means:

- inspection can see that a token was revoked
- later authorizations fail even if a copied token string still exists elsewhere

## Better Auth

`agent.pw` uses Better Auth as the provider OAuth engine.

The Better Auth bridge in `agent.pw/better-auth` does two things:

- exposes Better Auth tables inside the same `agentpw` SQL schema
- mirrors Better Auth account updates into encrypted Binding-scoped agent.pw credentials

Pending auth handoff state is intentionally storage-backend-agnostic. An embedding product can keep that state in SQL, KV, or another ephemeral store that matches its runtime needs.

That separation matters:

- Better Auth manages the OAuth handshake and provider account lifecycle
- agent.pw remains the runtime-facing source of truth for resolved credentials

## Storage

All framework-owned tables live in the `agentpw` schema.

Core tables:

- `cred_profiles`
- `credentials`
- `issued_tokens`
- `revocations`

Better Auth companion tables:

- `auth_users`
- `auth_sessions`
- `auth_accounts`
- `auth_verifications`

## Trust Boundary

The host application owns user auth, UI, and runtime orchestration.

`agent.pw` owns:

- path validation and resolution
- encrypted credential storage
- provider auth definitions
- Biscuit minting, attenuation, inspection, and revocation-aware authorization

That keeps the auth control plane inspectable and reusable across products without forcing a second server hop.
