# Security Model

`agent.pw` is built around three primitives:

- path-scoped `Credential Profiles`
- encrypted `Credentials`
- scoped Biscuit-based `Agent Access`

The framework does not own an HTTP surface. A host product embeds these primitives directly and decides how agents, users, and runtimes interact with them.

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

### Agent Access

`Agent Access` is a Biscuit token plus optional tracked metadata in `issued_tokens`.

Tokens carry:

- identity facts such as `user_id(...)`, `org_id(...)`, and `home_path(...)`
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

## Resolution

### Profile Resolution

Given a requested root, profiles resolve by applicability:

1. Find profiles whose parent path is an ancestor of the requested root.
2. Prefer the deepest applicable path.
3. Fall back to root-level defaults such as `/github` or `/linear`.
4. Same-depth ambiguity is an error.

This makes path-local overrides explicit without flattening provider knowledge into one global table.

### Credential Resolution

Credentials resolve the same way:

1. Filter by target host.
2. Keep credentials whose parent path is an ancestor of the requested root.
3. Choose the deepest applicable credential.
4. Same-depth ambiguity is an error.

This lets a product keep credentials portable while still narrowing them by org, workspace, or user subtree.

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

The framework enforces two things during authorization:

- the token still validates and has not been revoked
- the token’s explicit rights cover the requested path/action

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
- mirrors Better Auth account updates into encrypted agent.pw credentials

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
